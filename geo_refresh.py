"""Background daemon that keeps GeoIP DBs in sync with upstream release cadence.

Each backend has a setup script under `scripts/` that downloads + installs
the DB. The refresher fires the script when:

  - the DB file is missing, OR
  - the DB file is older than the backend's cadence_seconds

A successful run nudges `geo.invalidate_cache(name)` and `geo._BY_NAME
[name].refresh()` so the next lookup reopens the freshly-written file
without restarting the dashboard.

Cadence values are the publishing rhythm of the upstream provider:

  - GeoLite2:    twice a week (~3.5 days)
  - DB-IP:       monthly (~31 days; release lands on 1st)
  - IP2Location: monthly (~31 days; release lands on 1st)

The daemon checks every hour. Setup scripts that need a missing env var
(MAXMIND_LICENSE_KEY, IP2LOCATION_TOKEN) just exit non-zero — the
refresher logs and moves on instead of crashing the process.

Disable entirely with `GEO_REFRESH_DISABLED=1`. Override the check
interval with `GEO_REFRESH_INTERVAL_S` (default 3600).
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from typing import Optional

import geo

_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "scripts")

# Per-backend refresh config. Order matches geo._BACKENDS so logs read
# left-to-right the same way as the FE selector.
_SPECS = [
    {
        "name": "geolite2",
        "path": geo.GEOLITE2_PATH,
        "script": "setup_geolite2.sh",
        "env_required": ["MAXMIND_LICENSE_KEY"],
        "cadence_seconds": 3.5 * 24 * 3600,
    },
    {
        "name": "dbip",
        "path": geo.DBIP_PATH,
        "script": "setup_dbip.sh",
        "env_required": [],
        "cadence_seconds": 31 * 24 * 3600,
    },
    {
        "name": "ip2location",
        "path": geo.IP2LOCATION_PATH,
        "script": "setup_ip2location.sh",
        "env_required": ["IP2LOCATION_TOKEN"],
        "cadence_seconds": 31 * 24 * 3600,
    },
]


def _needs_refresh(spec: dict) -> tuple[bool, str]:
    """(should_refresh, reason). Reason is logged when True."""
    if not os.path.exists(spec["path"]):
        return True, "missing"
    try:
        age = time.time() - os.path.getmtime(spec["path"])
    except OSError:
        return True, "stat failed"
    if age >= spec["cadence_seconds"]:
        return True, f"stale ({int(age / 86400)}d > {int(spec['cadence_seconds'] / 86400)}d)"
    return False, ""


def _has_required_env(spec: dict) -> bool:
    return all(os.environ.get(v) for v in spec["env_required"])


def _run_once(spec: dict) -> Optional[bool]:
    """Run setup script for one backend.

    Returns True on a successful refresh, False on failure, None on skip
    (DB still fresh)."""
    should, reason = _needs_refresh(spec)
    if not should:
        return None
    name = spec["name"]
    if not _has_required_env(spec):
        missing = [v for v in spec["env_required"] if not os.environ.get(v)]
        print(f"[geo_refresh] {name}: skipped — missing env {missing}", flush=True)
        return False
    script = os.path.join(_SCRIPTS_DIR, spec["script"])
    if not os.path.exists(script):
        print(f"[geo_refresh] {name}: setup script not found at {script}", flush=True)
        return False
    print(f"[geo_refresh] {name}: refreshing ({reason})…", flush=True)
    try:
        proc = subprocess.run(
            ["bash", script],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=os.path.dirname(__file__),
        )
    except subprocess.TimeoutExpired:
        print(f"[geo_refresh] {name}: setup script timed out", flush=True)
        return False
    except Exception as e:
        print(f"[geo_refresh] {name}: setup script crashed — {e}", flush=True)
        return False
    if proc.returncode != 0:
        # stderr from these scripts is short + actionable (auth, network)
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
        print(f"[geo_refresh] {name}: setup failed rc={proc.returncode} — {' | '.join(tail)}", flush=True)
        return False
    print(f"[geo_refresh] {name}: refreshed OK", flush=True)
    # Drop the open reader so the next lookup sees the new file, and
    # evict cached answers (ensemble entries too).
    backend = geo._BY_NAME.get(name)
    if backend is not None:
        backend.refresh()
    geo.invalidate_cache(name)
    return True


def refresh_all_blocking() -> None:
    """Used at boot — run one pass synchronously so the first request
    after a cold start already has the freshest DBs available."""
    for spec in _SPECS:
        _run_once(spec)


_thread: Optional[threading.Thread] = None
_stop = threading.Event()


def _loop() -> None:
    interval = int(os.environ.get("GEO_REFRESH_INTERVAL_S", "3600"))
    while not _stop.is_set():
        for spec in _SPECS:
            try:
                _run_once(spec)
            except Exception as e:
                print(f"[geo_refresh] {spec['name']}: loop error — {e}", flush=True)
        _stop.wait(interval)


def start_daemon() -> None:
    """Idempotent. Spawned once from main.py at server boot."""
    global _thread
    if os.environ.get("GEO_REFRESH_DISABLED", "").lower() in ("1", "true", "yes"):
        print("[geo_refresh] disabled by env", flush=True)
        return
    if _thread is not None and _thread.is_alive():
        return
    # Boot-time pass is synchronous-ish but kicked into a thread so we
    # don't block the HTTP listener from binding while a 100MB MMDB
    # downloads. The dashboard renders "unknown location" for real IPs
    # during this window — same behavior as before.
    _thread = threading.Thread(target=_loop, name="geo-refresh", daemon=True)
    _thread.start()
    print("[geo_refresh] started", flush=True)
