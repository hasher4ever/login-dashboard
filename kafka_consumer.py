"""
Kafka consumer for the auth_events topic published by tms-auth.

Ravshan's payload (per DEV-660 delivery):
    {
        "attempt_id": str,
        "timestamp": str (ISO-8601),
        "success": bool,
        "email": str | null,
        "user_id": str | null,
        "company_id": str | null,
        "ip": str,
        "user_agent": str,
        "client_type": str,
        "failure_reason": str | null,
    }

We adapt this into the dashboard's internal event shape (which predates the
auth contract) and hand it to ingest_event(). Adapter rules:
- email -> username (dashboard column is labelled "user"; email is fine)
- timestamp ignored — ingest_event() stamps ts = now() so the live feed
  shows wall-clock arrival, which is what an SOC viewer wants. Original
  source timestamp is preserved in `source_ts` for forensics.

Configuration (env vars, all optional — absence = "no live mode"):
    KAFKA_BROKERS              comma-separated bootstrap servers
    KAFKA_TOPIC                default "auth_events"
    KAFKA_GROUP_ID             default "login-dashboard"
    KAFKA_SECURITY_PROTOCOL    PLAINTEXT (default) | SASL_PLAINTEXT | SASL_SSL
    KAFKA_SASL_MECHANISM       PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
    KAFKA_SASL_USERNAME
    KAFKA_SASL_PASSWORD

If KAFKA_BROKERS is unset the consumer is a no-op and start() returns False —
caller treats the dashboard as prototype/disconnected.
"""

import json
import logging
import os
import threading
import time
import uuid
from typing import Callable, Optional

import event_store

# Silence kafka-python's chatty internal loggers — Railway's deployment log
# rate limit is ~100 msgs/sec and the library's INFO/DEBUG level happily
# floods past that during reconnects.
logging.getLogger("kafka").setLevel(logging.WARNING)
logging.getLogger("kafka.conn").setLevel(logging.WARNING)
logging.getLogger("kafka.coordinator").setLevel(logging.WARNING)
logging.getLogger("kafka.client").setLevel(logging.WARNING)


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def kafka_configured() -> bool:
    return bool(_env("KAFKA_BROKERS"))


# Public health bits — main.py reads these for the status banner.
_status_lock = threading.Lock()
_status: dict = {
    "connected": False,
    "broker": _env("KAFKA_BROKERS", ""),
    "topic": _env("KAFKA_TOPIC", "auth_events"),
    "last_error": "",
    "last_message_at": 0.0,
    "messages_seen": 0,
}


def status() -> dict:
    with _status_lock:
        return dict(_status)


def _set(**kw) -> None:
    with _status_lock:
        _status.update(kw)


def _adapt(payload: dict) -> dict:
    """Map Ravshan's payload into the dashboard's event shape."""
    return {
        "success": bool(payload.get("success")),
        "ip": payload.get("ip") or "",
        "username": payload.get("email") or "(unknown)",
        "user_agent": payload.get("user_agent") or "",
        "failure_reason": payload.get("failure_reason"),
        # Extra fields kept on the event so future panels can use them.
        "source_ts": payload.get("timestamp"),
        "user_id": payload.get("user_id"),
        "company_id": payload.get("company_id"),
        "client_type": payload.get("client_type"),
        "attempt_id": payload.get("attempt_id"),
    }


def _build_consumer():
    """Lazy import — kafka-python is optional if you're running locally with mocks."""
    from kafka import KafkaConsumer  # type: ignore

    brokers = _env("KAFKA_BROKERS")
    topic = _env("KAFKA_TOPIC", "auth_events")
    # Ephemeral per-process group_id by default so each boot replays Kafka's
    # full retention into the buffer — without that, the windowed views
    # ("last 6 hours", "last 24 hours") are empty until enough live traffic
    # has accumulated. Operators can override with KAFKA_GROUP_ID for the
    # rare "I want to resume from where I left off" use case.
    group_id = _env("KAFKA_GROUP_ID", f"login-dashboard-{uuid.uuid4().hex[:8]}")
    sec = _env("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")

    kw = dict(
        bootstrap_servers=[b.strip() for b in brokers.split(",") if b.strip()],
        group_id=group_id,
        # Replay from the start of whatever Kafka still retains. Paired with
        # auto_commit=False so subsequent restarts (even within retention)
        # also start from earliest — there's no committed offset to resume
        # from. Practical history depth is bounded by min(Kafka retention,
        # BUFFER_SIZE events).
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")) if b else None,
        security_protocol=sec,
        # Default consumer_timeout_ms is float('inf') = block forever on empty
        # topic. We deliberately DO NOT override this: setting it to 0 makes
        # the iterator non-blocking and the outer reconnect loop tight-spins,
        # spamming Railway's log rate limit (~100 msg/sec).
        client_id="login-dashboard",
    )
    if sec.startswith("SASL"):
        kw["sasl_mechanism"] = _env("KAFKA_SASL_MECHANISM", "PLAIN")
        kw["sasl_plain_username"] = _env("KAFKA_SASL_USERNAME") or ""
        kw["sasl_plain_password"] = _env("KAFKA_SASL_PASSWORD") or ""
    return KafkaConsumer(topic, **kw)


# Batch parameters for the ClickHouse insert path. Tuned for "low signin
# volume most of the time, occasional bursts during attacks":
#   - flush every BATCH_MAX_ROWS events so a steady high-rate stream still
#     ships rows promptly (no unbounded buffer growth)
#   - flush every BATCH_MAX_AGE_S seconds so a trickle of 1-2 signins/min
#     doesn't sit in memory for hours before reaching CH
BATCH_MAX_ROWS = 200
BATCH_MAX_AGE_S = 0.5


def _flush_batch(batch: list[dict]) -> None:
    """Ship a batch to CH (if configured) and clear the buffer. Errors are
    swallowed inside event_store.insert_batch — caller need not handle
    failure here; the dashboard's in-memory deque + alert pipeline are
    independent of CH being up."""
    if not batch:
        return
    configured = event_store.ch_configured()
    # Diag (capped) — prove _flush_batch is being entered + the ch_configured
    # check passes. Caps at 5 prints so it doesn't fill the log forever.
    if status()["messages_seen"] < 50:
        print(f"[kafka] _flush_batch n={len(batch)} ch_configured={configured}", flush=True)
    if configured:
        event_store.insert_batch(batch)


def _consume_loop(on_event: Callable[[dict], None]) -> None:
    """Run forever — reconnect on any error after a short backoff.

    Each message is fanned out to:
      1) `on_event(ev)` — the in-process deque + alert recomputation
         (kept hot so brute_force / cred_stuffing alerts run real-time)
      2) the CH batch buffer — flushed every BATCH_MAX_ROWS events or
         BATCH_MAX_AGE_S seconds (whichever first)

    CH writes are best-effort: a CH outage doesn't stop the dashboard from
    serving the 5-minute in-memory view. Long-window queries (>5m) will
    return empty during the outage but the rest of the UI keeps working."""
    backoff = 1.0
    batch: list[dict] = []
    last_flush = time.time()
    while True:
        try:
            consumer = _build_consumer()
            _set(connected=True, last_error="")
            print(
                f"[kafka] connected — brokers={_env('KAFKA_BROKERS')} topic={_env('KAFKA_TOPIC', 'auth_events')}",
                flush=True,
            )
            backoff = 1.0
            for msg in consumer:
                try:
                    payload = msg.value
                    if not isinstance(payload, dict):
                        continue
                    ev = _adapt(payload)
                    on_event(ev)
                    batch.append(ev)
                    seen_before = status()["messages_seen"]
                    _set(
                        last_message_at=time.time(),
                        messages_seen=seen_before + 1,
                    )
                    # Per-event log so "did anything flow through" is answerable
                    # without an in-browser test. Compact; success/failure +
                    # email + ip is enough for visual scanning. The first
                    # message gets an extra prefix so the "wiring works" moment
                    # is unmistakable in the log stream.
                    verdict = "OK" if ev["success"] else f"FAIL/{ev.get('failure_reason') or 'unknown'}"
                    prefix = "[kafka] first event! " if seen_before == 0 else "[kafka] ingest "
                    print(
                        f"{prefix}{verdict} email={ev['username']!r} ip={ev['ip']}",
                        flush=True,
                    )
                except Exception as e:  # noqa: BLE001 — keep the loop alive on bad payloads
                    print(f"[kafka] bad message dropped: {e}", flush=True)

                # Flush if the batch hit its row cap or its age cap
                now_ts = time.time()
                age = now_ts - last_flush
                size_ok = len(batch) >= BATCH_MAX_ROWS
                age_ok = bool(batch) and age >= BATCH_MAX_AGE_S
                # Diag: log every checkpoint at batch milestones until we
                # observe one successful flush.
                seen = status()["messages_seen"]
                if seen in (1, 5, 50, 100, 200, 300) or size_ok or age_ok:
                    print(
                        f"[kafka] flush-check seen={seen} len(batch)={len(batch)} "
                        f"now={now_ts:.6f} last_flush={last_flush:.6f} age={age:.6f}s "
                        f"size_ok={size_ok} age_ok={age_ok}",
                        flush=True,
                    )
                if size_ok or age_ok:
                    _flush_batch(batch)
                    batch = []
                    last_flush = now_ts
            # Defensive: if the iterator exits without raising (shouldn't
            # happen with the default infinite timeout, but guard anyway so
            # we can never tight-loop), sleep before reconnecting.
            _flush_batch(batch)
            batch = []
            _set(connected=False, last_error="iterator returned cleanly")
            print("[kafka] iterator exited cleanly — pausing 5s before reconnect", flush=True)
            time.sleep(5)
        except Exception as e:  # noqa: BLE001
            _flush_batch(batch)
            batch = []
            _set(connected=False, last_error=str(e))
            print(f"[kafka] disconnected: {e} — retry in {backoff:.0f}s", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)


def start(on_event: Callable[[dict], None]) -> bool:
    """Spawn the consumer thread. Returns False if no broker is configured."""
    if not kafka_configured():
        print("[kafka] KAFKA_BROKERS not set — dashboard runs in disconnected mode", flush=True)
        return False
    t = threading.Thread(target=_consume_loop, args=(on_event,), daemon=True, name="kafka-consumer")
    t.start()
    return True
