"""
ClickHouse-backed persistence for sign-in events.

Why CH and not Postgres / SQLite:
- TMS360 already runs a ClickHouse service (used by backend-audit and
  backend-asset-tracking); reusing it follows the org pattern
- Time-series shape: ReplacingMergeTree + monthly partition + 90-day TTL
  gives cheap retention and bounded storage with no maintenance
- Window queries (`last 24 hours by IP`) are the access pattern CH was
  built for; sub-second p99 on millions of rows

Protocol choice: the TMS360 CH instance rejects HTTP Basic auth (8123) — the
backend-audit service connects successfully on port 9000 with the native TCP
protocol, and we follow that path. Library: `clickhouse-driver`. Pure-Python
client with a small cityhash C extension (the Dockerfile already provides
gcc for python-snappy so this builds without extra work).

Read paths that hit this module: aggregates_snapshot / map_markers_json /
feed_json / render_live_panel. Alert recomputation deliberately stays in
the in-memory deque because it runs per-ingest with 30-60s windows —
hitting CH 100s of times/sec under attack would burn the DB for no gain.

Write path: kafka_consumer batches up to BATCH_MAX_ROWS or BATCH_MAX_AGE_S
worth of events and ships them in a single INSERT.

Failure semantics: every public method swallows transport errors and logs
them. Callers (the kafka consumer, the HTTP handlers) keep working — CH
being down does NOT take the dashboard down. The status() result feeds
the header pill so an operator can see CH state at a glance.
"""

import logging
import os
import threading
import time
from typing import Optional

# clickhouse-driver's Client; lazy-imported so the dashboard can boot without
# it installed (useful for local-only dev when CH isn't configured).
_client = None
_client_lock = threading.Lock()
_status = {
    "configured": False,
    "connected": False,
    "last_error": "",
    "last_insert_at": 0.0,
    "rows_inserted": 0,
    "last_query_at": 0.0,
}

TABLE = "security_auth_events"

# clickhouse-driver's INFO logger emits one line per query by default; cap to
# WARNING so the Railway 100-msg/sec rate limit doesn't get blown by chatter
# during a Kafka replay storm.
logging.getLogger("clickhouse_driver").setLevel(logging.WARNING)


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def ch_configured() -> bool:
    return bool(_env("CLICKHOUSE_HOST"))


def status() -> dict:
    return dict(_status)


def _get_client():
    """Lazy-build the Client. Caches on success; on failure clears the cache
    so the next call retries (transient connect errors shouldn't poison the
    process for its lifetime)."""
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        try:
            from clickhouse_driver import Client  # type: ignore
        except ImportError:
            _status["last_error"] = "clickhouse-driver not installed"
            return None
        host = _env("CLICKHOUSE_HOST")
        if not host:
            _status["last_error"] = "CLICKHOUSE_HOST not set"
            return None
        # Native TCP port. backend-audit uses 9000 successfully against this
        # cluster; HTTP (8123) auth is rejected.
        port = int(_env("CLICKHOUSE_PORT", "9000") or "9000")
        user = _env("CLICKHOUSE_USERNAME", "default") or "default"
        password = _env("CLICKHOUSE_PASSWORD", "") or ""
        database = _env("CLICKHOUSE_DATABASE", "default") or "default"
        try:
            _client = Client(
                host=host,
                port=port,
                user=user,
                password=password,
                database=database,
                # Don't pin secure=True — Railway-internal traffic doesn't go
                # through TLS and TLS-on-internal is uncommon for CH. If we
                # ever connect to a TLS-fronted CH we'll add it as an env.
                connect_timeout=10,
                send_receive_timeout=15,
                # Keep one socket open for the process lifetime — we batch
                # inserts and want low per-batch overhead.
                settings={"use_numpy": False},
            )
            # Force an early auth round-trip so we know connect is good
            # before the first batch tries to flush.
            _client.execute("SELECT 1")
            _status["configured"] = True
            _status["connected"] = True
            _status["last_error"] = ""
            print(f"[ch] connected — {host}:{port} db={database} user={user}", flush=True)
            return _client
        except Exception as e:  # noqa: BLE001
            _status["configured"] = True
            _status["connected"] = False
            _status["last_error"] = str(e)[:200]
            print(f"[ch] connect failed: {e}", flush=True)
            _client = None
            return None


def _reset_client_on_error():
    """Drop the cached client so the next call re-connects. Use after any
    transport-level error."""
    global _client
    with _client_lock:
        try:
            if _client is not None:
                _client.disconnect()
        except Exception:  # noqa: BLE001
            pass
        _client = None


# ---------- schema -----------------------------------------------------------

SCHEMA_DDL = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    attempt_id      String,
    event_time      DateTime64(3, 'UTC'),
    ingest_time     DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
    success         UInt8,
    email           String,
    user_id         Nullable(String),
    company_id      Nullable(String),
    ip              String,
    user_agent      String,
    client_type     LowCardinality(String),
    failure_reason  LowCardinality(String),
    INDEX idx_ip ip TYPE bloom_filter GRANULARITY 3
)
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_time, attempt_id)
TTL toDateTime(event_time) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192
"""


def ensure_schema() -> bool:
    """Idempotently create the events table. Returns True on success.

    Safe to call on every boot — CREATE TABLE IF NOT EXISTS is a no-op when
    the table already exists. If CH is down or unreachable we log and
    return False; the dashboard's other read paths will fall back to the
    in-memory deque, and ensure_schema() retries on the next boot."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.execute(SCHEMA_DDL)
        print(f"[ch] schema ready — table {TABLE}", flush=True)
        return True
    except Exception as e:  # noqa: BLE001
        _status["last_error"] = str(e)[:200]
        _status["connected"] = False
        _reset_client_on_error()
        print(f"[ch] schema setup failed: {e}", flush=True)
        return False


# ---------- writes -----------------------------------------------------------

INSERT_COLUMNS = (
    "attempt_id",
    "event_time",
    "success",
    "email",
    "user_id",
    "company_id",
    "ip",
    "user_agent",
    "client_type",
    "failure_reason",
)
INSERT_SQL = (
    f"INSERT INTO {TABLE} ({', '.join(INSERT_COLUMNS)}) VALUES"
)


def _row_from_event(ev: dict) -> tuple:
    """Adapter from the dashboard's internal event shape to the CH row order
    above. `ev` is what kafka_consumer._adapt() produced. Missing/null
    values are coerced to safe defaults so a single bad message never
    poisons a batch."""
    from datetime import datetime, timezone
    # event_time: prefer the source timestamp from tms-auth; fall back to now
    src = ev.get("source_ts")
    if src:
        try:
            event_time = datetime.fromisoformat(str(src).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            event_time = datetime.now(tz=timezone.utc)
    else:
        event_time = datetime.now(tz=timezone.utc)

    return (
        str(ev.get("attempt_id") or ""),
        event_time,
        1 if ev.get("success") else 0,
        str(ev.get("username") or ""),
        ev.get("user_id") or None,
        ev.get("company_id") or None,
        str(ev.get("ip") or ""),
        str(ev.get("user_agent") or ""),
        str(ev.get("client_type") or ""),
        str(ev.get("failure_reason") or ""),
    )


def insert_batch(events: list[dict]) -> bool:
    """Batch-insert events. Returns True on success.

    On failure: marks status disconnected, drops the cached client (so the
    next batch retries the connection), and returns False. The caller
    (kafka consumer) keeps draining its own buffer; it's free to retry
    immediately or drop the batch — current policy is drop, because
    re-buffering forever on a long CH outage is worse than missing some
    historical writes (the in-memory deque + alert pipeline still works)."""
    if not events:
        return True
    client = _get_client()
    if client is None:
        return False
    rows = [_row_from_event(e) for e in events]
    try:
        client.execute(INSERT_SQL, rows)
        _status["last_insert_at"] = time.time()
        _status["rows_inserted"] += len(rows)
        _status["connected"] = True
        return True
    except Exception as e:  # noqa: BLE001
        _status["last_error"] = str(e)[:200]
        _status["connected"] = False
        _reset_client_on_error()
        print(f"[ch] insert batch failed (dropped {len(rows)} rows): {e}", flush=True)
        return False


# ---------- reads ------------------------------------------------------------

def query_aggregates(window_s: int) -> list[dict]:
    """Per-IP aggregate over the last `window_s` seconds.

    Returns a list of dicts shaped like the legacy aggregates_snapshot()
    output so the HTTP handler / map JSON path doesn't need to change.
    On any error: returns empty list and the caller will fall back to
    the in-memory deque — a stale read is worse than an empty read."""
    client = _get_client()
    if client is None:
        return []
    sql = f"""
        SELECT
            ip,
            countIf(success = 1) AS ok,
            countIf(success = 0) AS fail,
            max(event_time)                AS last_ts,
            argMax(email, event_time)      AS last_user,
            argMax(user_agent, event_time) AS last_ua
        FROM {TABLE}
        WHERE event_time >= now() - toIntervalSecond({int(window_s)})
        GROUP BY ip
        ORDER BY fail DESC, last_ts DESC
        LIMIT 500
    """
    try:
        rows = client.execute(sql)
        _status["last_query_at"] = time.time()
        _status["connected"] = True
        out = []
        for ip, ok, fail, last_ts, last_user, last_ua in rows:
            out.append({
                "ip": ip,
                "ok": int(ok),
                "fail": int(fail),
                "last_user": last_user or "",
                "last_ua": last_ua or "",
                # CH DateTime → unix float so existing render code (which
                # expects ev['ts'] as unix) works untouched.
                "last_ts": last_ts.timestamp() if last_ts is not None else 0.0,
            })
        return out
    except Exception as e:  # noqa: BLE001
        _status["last_error"] = str(e)[:200]
        _status["connected"] = False
        _reset_client_on_error()
        print(f"[ch] query_aggregates failed: {e}", flush=True)
        return []


def query_recent(limit: int = 100) -> list[dict]:
    """Newest-first event list for the Live tab + side feed.

    Matches the internal event dict shape ingest_event() builds so existing
    render code is unchanged."""
    client = _get_client()
    if client is None:
        return []
    sql = f"""
        SELECT event_time, success, email, ip, user_agent, failure_reason
        FROM {TABLE}
        ORDER BY event_time DESC
        LIMIT {int(limit)}
    """
    try:
        rows = client.execute(sql)
        _status["last_query_at"] = time.time()
        _status["connected"] = True
        out = []
        for event_time, success, email, ip, user_agent, failure_reason in rows:
            out.append({
                "ts": event_time.timestamp() if event_time is not None else 0.0,
                "success": bool(success),
                "username": email or "",
                "ip": ip or "",
                "user_agent": user_agent or "",
                "failure_reason": failure_reason or "",
            })
        return out
    except Exception as e:  # noqa: BLE001
        _status["last_error"] = str(e)[:200]
        _status["connected"] = False
        _reset_client_on_error()
        print(f"[ch] query_recent failed: {e}", flush=True)
        return []


def total_rows() -> int:
    """One-glance count for the source banner. Returns 0 on error so the
    pill renders zero rather than crashing the page."""
    client = _get_client()
    if client is None:
        return 0
    try:
        rows = client.execute(f"SELECT count() FROM {TABLE}")
        return int(rows[0][0]) if rows else 0
    except Exception as e:  # noqa: BLE001
        _status["last_error"] = str(e)[:200]
        return 0
