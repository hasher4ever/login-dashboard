"""
login-dashboard — live monitor for TMS360 sign-in attempts.

Data sources, both optional:
- **Kafka** topic `auth_events` (per DEV-660). Set KAFKA_BROKERS to enable.
- **GraphQL** ipAccessRules + ban/allow/block mutations on tms-auth. Set
  AUTH_JWT (and AUTH_GRAPHQL_URL if non-default) to enable.

With neither configured the dashboard runs in disconnected mode: the
ENABLE_SCENARIOS=true flag exposes the canned scenario buttons for demo.
"""

import html
import json
import os
import queue
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from geo import geolocate
from scenarios import SCENARIOS
import kafka_consumer
import graphql_client
import auth_session

PORT = int(os.environ.get("PORT", "8000"))
ENABLE_SCENARIOS = os.environ.get("ENABLE_SCENARIOS", "").lower() in ("1", "true", "yes")
# Set COOKIE_INSECURE=true only when running on plain http:// (local dev). On
# Railway the default Secure flag is what we want.
COOKIE_INSECURE = os.environ.get("COOKIE_INSECURE", "").lower() in ("1", "true", "yes")
BUFFER_SIZE = 10000        # event ring buffer — caps how much history any window can show
RULES_REFRESH_S = 30       # how often to re-pull ipAccessRules from tms-auth
ALERT_WINDOW_S = {
    "brute_force": 30,
    "cred_stuffing": 60,
    "geo_anomaly": 300,
}

# User-facing time-window picker. Cookie `dashboard_window` overrides the
# default; every snapshot/render reads it per-request so changing the
# dropdown takes effect on the next refresh tick (no process restart).
WINDOW_COOKIE = "dashboard_window"
DEFAULT_WINDOW_S = 300
WINDOW_PRESETS: list[tuple[int, str]] = [
    (300, "5 minutes"),
    (900, "15 minutes"),
    (3600, "1 hour"),
    (21600, "6 hours"),
    (86400, "24 hours"),
]
WINDOW_MIN_S = 60
WINDOW_MAX_S = 86400 * 7   # cap at 7 days; longer would need a real store
ALERT_TTL_S = 120          # alerts hang around 2 minutes after firing

# ---------- mutable state (guarded by lock) ----------------------------------
state_lock = threading.Lock()
events: deque = deque(maxlen=BUFFER_SIZE)
# Per-IP rule registries. Value carries `rule_id` (server-issued, needed for
# removeIPRule) plus `reason` and (for bans) `expires_at` unix-ts.
bans: dict[str, dict] = {}
allowlist: dict[str, dict] = {}
blocklist: dict[str, dict] = {}
alerts: list[dict] = []            # {at, kind, key, detail}
sse_subs: list[queue.Queue] = []
auth_status: dict = {"last_refresh": 0.0, "ok": False, "error": ""}


# ---------- helpers ----------------------------------------------------------
def now() -> float:
    return time.time()


def iso(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def slash16(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else ip


def log(msg: str) -> None:
    print(f"[{iso(now())}] {msg}", file=sys.stderr, flush=True)


# ---------- SSE fan-out ------------------------------------------------------
# Throttle SSE broadcasts to at most one per BROADCAST_MIN_INTERVAL_S. Without
# this, a Kafka replay storm (potentially thousands of events delivered in a
# few seconds at boot) would fire one SSE update per ingest, overflow every
# subscriber's 200-deep queue, and either kill browsers under refresh load
# or get them disconnected. Surplus broadcasts are dropped — the panels'
# hx-trigger="every 5s" fallback fills the gap.
BROADCAST_MIN_INTERVAL_S = 0.25
_broadcast_lock = threading.Lock()
_last_broadcast_ts = 0.0


def broadcast(event: str = "update", data: str = "ok") -> None:
    global _last_broadcast_ts
    with _broadcast_lock:
        n = time.time()
        if n - _last_broadcast_ts < BROADCAST_MIN_INTERVAL_S:
            return
        _last_broadcast_ts = n

    payload = f"event: {event}\ndata: {data}\n\n"
    dead = []
    with state_lock:
        subs = list(sse_subs)
    for q in subs:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)
    if dead:
        with state_lock:
            for q in dead:
                if q in sse_subs:
                    sse_subs.remove(q)


def sse_pinger():
    while True:
        time.sleep(20)
        broadcast(event="ping", data="keepalive")


# ---------- ingestion + alert rules ------------------------------------------
def _parse_source_ts(s: Optional[str]) -> Optional[float]:
    """Best-effort ISO-8601 → unix seconds. None on missing/garbage so the
    caller can fall back to wall-clock now()."""
    if not s:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def ingest_event(ev: dict) -> None:
    """Append an event, update bans/alerts, and notify subscribers.

    Stamps ev['ts'] with the SOURCE timestamp (when tms-auth produced) when
    available, falling back to now(). This is what makes "last 6 hours"
    windows honest during boot-time Kafka replay — a replayed event from
    3 hours ago is treated as 3 hours ago, not as just-arrived."""
    ev = dict(ev)
    ev["ts"] = _parse_source_ts(ev.get("source_ts")) or now()
    with state_lock:
        events.append(ev)
        _recompute_alerts_locked()
    broadcast()


def _recompute_alerts_locked() -> None:
    """Fire alert entries based on current event buffer. Lock must be held."""
    n = now()

    # Prune expired alerts
    alerts[:] = [a for a in alerts if n - a["at"] < ALERT_TTL_S]

    # Snapshot window slices
    win_bf = ALERT_WINDOW_S["brute_force"]
    win_cs = ALERT_WINDOW_S["cred_stuffing"]
    win_ga = ALERT_WINDOW_S["geo_anomaly"]

    recent_bf = [e for e in events if n - e["ts"] <= win_bf]
    recent_cs = [e for e in events if n - e["ts"] <= win_cs]
    recent_ga = [e for e in events if n - e["ts"] <= win_ga]

    # Rule 1: brute_force — IP with >= 5 fails in last 30s
    fail_counts: dict[str, int] = {}
    for e in recent_bf:
        if not e["success"]:
            fail_counts[e["ip"]] = fail_counts.get(e["ip"], 0) + 1
    for ip, ct in fail_counts.items():
        if ct >= 5:
            _upsert_alert("brute_force", ip,
                          f"{ct} failures in last {win_bf}s")

    # Rule 2: cred_stuffing — username attempted by >= 3 distinct IPs in 60s
    user_ips: dict[str, set] = {}
    for e in recent_cs:
        user_ips.setdefault(e["username"], set()).add(e["ip"])
    for user, ips in user_ips.items():
        if len(ips) >= 3:
            _upsert_alert("cred_stuffing", user,
                          f"{len(ips)} distinct IPs in last {win_cs}s")

    # Rule 3: geo_anomaly — same user, successful, two distinct /16 prefixes
    user_prefixes: dict[str, set] = {}
    for e in recent_ga:
        if e["success"]:
            user_prefixes.setdefault(e["username"], set()).add(slash16(e["ip"]))
    for user, pfx in user_prefixes.items():
        if len(pfx) >= 2:
            _upsert_alert("geo_anomaly", user,
                          f"same user from {len(pfx)} IP prefixes in {win_ga}s")


def _upsert_alert(kind: str, key: str, detail: str) -> None:
    for a in alerts:
        if a["kind"] == kind and a["key"] == key:
            a["at"] = now()
            a["detail"] = detail
            return
    alerts.append({"at": now(), "kind": kind, "key": key, "detail": detail})


# ---------- aggregation for the table ---------------------------------------
def _classify(ip: str, ban_map: dict, allow: dict, block: dict, n: float) -> tuple[str, str]:
    """Apply Ravshan's precedence: allow > block > ban > clean."""
    if ip in allow:
        return "allowlist", "Allow-listed"
    if ip in block:
        return "blocklist", "Blocked"
    if ip in ban_map and ban_map[ip]["expires_at"] > n:
        return "banned", f"Banned until {iso(ban_map[ip]['expires_at'])}"
    return "clean", ""


def fmt_window(seconds: int) -> str:
    """Render a window length as a human label: '5 minutes', '6 hours', '2 days'."""
    if seconds < 3600:
        m = seconds // 60
        return f"{m} minute{'s' if m != 1 else ''}"
    if seconds < 86400:
        h = seconds // 3600
        return f"{h} hour{'s' if h != 1 else ''}"
    d = seconds // 86400
    return f"{d} day{'s' if d != 1 else ''}"


def aggregates_snapshot(window_s: int) -> list[dict]:
    n = now()
    with state_lock:
        recent = [e for e in events if n - e["ts"] <= window_s]
        ban_map = dict(bans)
        allow = dict(allowlist)
        block = dict(blocklist)
    by_ip: dict[str, dict] = {}
    for e in recent:
        row = by_ip.setdefault(e["ip"], {
            "ip": e["ip"], "ok": 0, "fail": 0,
            "last_user": "", "last_ua": "", "last_ts": 0,
        })
        if e["success"]:
            row["ok"] += 1
        else:
            row["fail"] += 1
        if e["ts"] > row["last_ts"]:
            row["last_ts"] = e["ts"]
            row["last_user"] = e["username"]
            row["last_ua"] = e["user_agent"]
    rows = list(by_ip.values())
    rows.sort(key=lambda r: (r["fail"], r["last_ts"]), reverse=True)
    for r in rows:
        r["status"], r["status_label"] = _classify(r["ip"], ban_map, allow, block, n)
    return rows


# ---------- HTML rendering ---------------------------------------------------
TAB_DEFS = [
    ("ips",    "IPs",    "Aggregates by IP"),
    ("alerts", "Alerts", "Rule firings"),
    ("live",   "Live",   "Full feed history"),
    ("map",    "Map",    "Geo + live feed (80/20)"),
    ("bans",   "Bans",   "Active bans + allowlist"),
]


# Geo lookup lives in geo.py — MaxMind GeoLite2-City offline MMDB with an
# IP_GEO override table for the RFC5737 mock IPs used by scenarios.py.


def _source_banner(session: Optional[dict] = None) -> str:
    """Header pills: Kafka source state + auth-sync state + signed-in user."""
    k = kafka_consumer.status()
    parts = []
    if kafka_consumer.kafka_configured():
        if k["connected"]:
            parts.append(f'<span class="tag tag-live">LIVE · kafka {html.escape(k["topic"])}</span>')
        else:
            err = (k["last_error"] or "connecting…")[:60]
            parts.append(f'<span class="tag tag-warn">KAFKA · {html.escape(err)}</span>')
    else:
        parts.append('<span class="tag tag-warn">no KAFKA_BROKERS</span>')

    if session:
        parts.append(
            f'<span class="tag tag-live">{html.escape(session["email"])}</span>'
            f'<a class="tag tag-ghost" href="/logout">logout</a>'
        )
    else:
        parts.append('<span class="tag tag-warn">not signed in</span>')

    if auth_status["ok"]:
        parts.append('<span class="tag tag-live">rules synced</span>')
    elif auth_status["error"]:
        err = auth_status["error"][:60]
        parts.append(f'<span class="tag tag-warn">rules · {html.escape(err)}</span>')
    return "".join(parts)


def _scenarios_bar() -> str:
    if not ENABLE_SCENARIOS:
        return ""
    return """
  <div class="scenarios">
    <button hx-post="/scenario/steady_state"  hx-swap="none">▶ steady_state</button>
    <button hx-post="/scenario/brute_force"   hx-swap="none" class="danger">▶ brute_force</button>
    <button hx-post="/scenario/cred_stuffing" hx-swap="none" class="danger">▶ cred_stuffing</button>
    <button hx-post="/scenario/geo_anomaly"   hx-swap="none" class="warn">▶ geo_anomaly</button>
    <button hx-post="/scenario/clear"         hx-swap="none" class="ghost">⨯ clear</button>
  </div>"""


def _window_picker(current: int) -> str:
    """Compact <select> rendered in the header. Pre-selects whichever preset
    matches the current cookie value; falls back to showing the literal
    seconds value if the user has a custom one (set via cookie directly).
    onChange writes a year-long cookie and reloads so every panel re-renders
    against the new window in a single tick."""
    preset_values = {s for s, _ in WINDOW_PRESETS}
    options = []
    for s, label in WINDOW_PRESETS:
        sel = " selected" if s == current else ""
        options.append(f'<option value="{s}"{sel}>last {label}</option>')
    if current not in preset_values:
        options.append(
            f'<option value="{current}" selected>last {html.escape(fmt_window(current))}</option>'
        )
    return (
        '<select class="window-picker" onchange="setWindow(this.value)">'
        + "".join(options)
        + "</select>"
    )


def render_page(
    session: Optional[dict] = None,
    window_s: int = DEFAULT_WINDOW_S,
    active: str = "map",
) -> str:
    tabs = []
    for slug, label, _desc in TAB_DEFS:
        cls = "tab active" if slug == active else "tab"
        if slug == "map":
            # Map tab uses JS toggle, NOT HTMX swap, so the persistent map
            # DOM survives across tab switches and SSE ticks. This is the
            # default tab — page loads with it visible.
            tabs.append(
                f'<button class="{cls}" onclick="showMap(this); return false;">'
                f'{label}</button>'
            )
        else:
            tabs.append(
                f'<button class="{cls}" '
                f'hx-get="/partials/{slug}" hx-target="#content" hx-swap="outerHTML" '
                f'onclick="hideMap(this);">'
                f'{label}</button>'
            )
    tab_bar = "\n".join(tabs)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login Monitor — TMS360</title>
<script src="https://unpkg.com/htmx.org@2.0.3"></script>
<script src="https://unpkg.com/htmx-ext-sse@2.2.2"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>{CSS}</style>
</head>
<body>
<header>
  <div class="title">
    Login Monitor
    {_source_banner(session)}
  </div>
  <div class="header-controls">
    {_window_picker(window_s)}
    {_scenarios_bar()}
  </div>
</header>

<nav class="tabs">{tab_bar}</nav>

<main hx-ext="sse" sse-connect="/events" class="{'show-map' if active == 'map' else ''}">
  <div id="content"
       hx-get="/partials/{active if active != 'map' else 'ips'}"
       hx-trigger="load, sse:update, every 5s"
       hx-swap="outerHTML">
    Loading…
  </div>

  <!-- Persistent map+feed container; toggled by `main.show-map` CSS class.
       Using a class on the parent (rather than inline style on the wrapper)
       so HTMX swaps inside #content cannot clobber visibility state. -->
  <div id="map-wrapper">
    <div class="map-split">
      <section class="panel map-panel">
        <h2>Geographic distribution <span id="map-stat" class="muted"></span></h2>
        <div class="map-legend">
          <span class="dot" style="background:#6cb2ff"></span>clean
          <span class="dot" style="background:#ffc14a"></span>mixed
          <span class="dot" style="background:#ff8a96"></span>hot
          <span class="dot" style="background:#ff4d63"></span>banned
          <span class="dot" style="background:#6cdb8c"></span>allowlisted
          <span style="flex:1"></span>
          <button class="ghost" onclick="refreshMarkers();">↻ refresh</button>
        </div>
        <div id="login-map"></div>
      </section>
      <section class="panel side-feed-panel">
        <h2>Live feed <span id="feed-stat" class="muted"></span></h2>
        <div id="feed-side">
          <p class="muted">Waiting for events… (click a scenario above)</p>
        </div>
      </section>
    </div>
  </div>
</main>

<script>{MAP_JS}</script>
</body>
</html>"""


def _wrap(slug: str, inner: str) -> str:
    """Wrap a tab's body in a fresh #content div with its own hx-get + sse trigger."""
    return (
        f'<div id="content" '
        f'hx-get="/partials/{slug}" '
        f'hx-trigger="sse:update, every 5s" '
        f'hx-swap="outerHTML">'
        f'{inner}'
        f'</div>'
    )


def render_ips_panel(window_s: int = DEFAULT_WINDOW_S) -> str:
    rows = aggregates_snapshot(window_s)
    inner = f"""
<section class="panel">
  <h2>Aggregates by IP <span class="muted">(last {fmt_window(window_s)}, sorted by fail count)</span></h2>
  {_render_agg_table(rows, now())}
</section>"""
    return _wrap("ips", inner)


def render_alerts_panel() -> str:
    with state_lock:
        cur_alerts = sorted(alerts, key=lambda a: a["at"], reverse=True)
    inner = f"""
<section class="panel">
  <h2>Active alerts <span class="muted">(rule-based, auto-expire after {ALERT_TTL_S // 60} min idle)</span></h2>
  {_render_alerts(cur_alerts)}
</section>"""
    return _wrap("alerts", inner)


def render_live_panel() -> str:
    with state_lock:
        feed = list(events)[-100:]
    feed.reverse()
    inner = f"""
<section class="panel">
  <h2>Live feed <span class="muted">({len(events)} buffered, showing last {len(feed)})</span></h2>
  {_render_feed(feed)}
</section>"""
    return _wrap("live", inner)


def feed_json() -> str:
    """JSON payload for the side feed: most recent events, newest first."""
    with state_lock:
        snap = list(events)
        total = len(events)
    snap.reverse()
    out = []
    for e in snap[:80]:
        out.append({
            "ts": iso(e["ts"]),
            "success": e["success"],
            "ip": e["ip"],
            "username": e["username"],
        })
    return json.dumps({"events": out, "total": total})


def map_markers_json(window_s: int = DEFAULT_WINDOW_S) -> str:
    """JSON payload for the Map tab. Pure data, no HTML."""
    n = now()
    with state_lock:
        recent = [e for e in events if n - e["ts"] <= window_s]
        ban_map = dict(bans)
        allow = dict(allowlist)
        block = dict(blocklist)
    by_ip: dict[str, dict] = {}
    for e in recent:
        row = by_ip.setdefault(e["ip"], {"ok": 0, "fail": 0, "last_user": "", "last_ts": 0})
        if e["success"]:
            row["ok"] += 1
        else:
            row["fail"] += 1
        if e["ts"] > row["last_ts"]:
            row["last_ts"] = e["ts"]
            row["last_user"] = e["username"]
    markers = []
    for ip, row in by_ip.items():
        lat, lng, label = geolocate(ip)
        if ip in allow:
            color, status = "#6cdb8c", "allowlisted"
        elif ip in block:
            color, status = "#ff4d63", "blocked"
        elif ip in ban_map and ban_map[ip]["expires_at"] > n:
            color, status = "#ff4d63", "banned"
        elif row["fail"] >= 5:
            color, status = "#ff8a96", "hot"
        elif row["fail"] > 0:
            color, status = "#ffc14a", "mixed"
        else:
            color, status = "#6cb2ff", "clean"
        markers.append({
            "ip": ip, "lat": lat, "lng": lng, "label": label,
            "ok": row["ok"], "fail": row["fail"],
            "user": row["last_user"], "color": color, "status": status,
        })
    return json.dumps({
        "markers": markers,
        "window_label": fmt_window(window_s),
    })


def render_bans_panel() -> str:
    n = now()
    with state_lock:
        cur_bans = [(ip, entry) for ip, entry in bans.items() if entry["expires_at"] > n]
        cur_allow = list(allowlist.items())
        cur_block = list(blocklist.items())
    cur_bans.sort(key=lambda b: b[1]["expires_at"])
    cur_allow.sort(key=lambda x: x[0])
    cur_block.sort(key=lambda x: x[0])
    inner = f"""
<section class="panel">
  <h2>Banned IPs <span class="muted">({len(cur_bans)} active · auto-expire)</span></h2>
  {_render_bans_table(cur_bans, n)}
</section>

<section class="panel">
  <h2>Blocklist <span class="muted">({len(cur_block)} entries · permanent)</span></h2>
  {_render_block_table(cur_block)}
</section>

<section class="panel">
  <h2>Allowlist <span class="muted">({len(cur_allow)} entries · beats everything)</span></h2>
  {_render_allow_table(cur_allow)}
</section>"""
    return _wrap("bans", inner)


def _render_agg_table(rows: list[dict], n: float) -> str:
    if not rows:
        return '<p class="muted">No events yet. Click a scenario above to play.</p>'
    body = []
    for r in rows:
        action = _render_action_cell(r)
        cls = "row-banned" if r["status"] == "banned" else \
              "row-allow"   if r["status"] == "allowlist" else \
              "row-hot"     if r["fail"] >= 5 else ""
        body.append(f"""
<tr class="{cls}">
  <td class="ip">{html.escape(r["ip"])}</td>
  <td class="num ok">{r["ok"]}</td>
  <td class="num fail">{r["fail"]}</td>
  <td>{html.escape(r["last_user"])}</td>
  <td class="ua">{html.escape(_short_ua(r["last_ua"]))}</td>
  <td class="ts">{iso(r["last_ts"]) if r["last_ts"] else ""}</td>
  <td class="status">{html.escape(r["status_label"])}</td>
  <td class="actions">{action}</td>
</tr>""")
    return f"""<table class="agg">
<thead><tr>
  <th>IP</th><th>OK</th><th>FAIL</th><th>Last user</th>
  <th>UA</th><th>Last seen</th><th>Status</th><th>Action</th>
</tr></thead>
<tbody>{''.join(body)}</tbody>
</table>"""


def _render_action_cell(r: dict) -> str:
    ip = html.escape(r["ip"])
    if r["status"] == "banned":
        return f"""<form hx-post="/unban" hx-swap="none" class="inline">
          <input type="hidden" name="ip" value="{ip}">
          <button class="ghost">Unban</button>
        </form>"""
    if r["status"] == "allowlist":
        return f"""<form hx-post="/unallow" hx-swap="none" class="inline">
          <input type="hidden" name="ip" value="{ip}">
          <button class="ghost">Remove from allow</button>
        </form>"""
    if r["status"] == "blocklist":
        return f"""<form hx-post="/unblock" hx-swap="none" class="inline">
          <input type="hidden" name="ip" value="{ip}">
          <button class="ghost">Unblock</button>
        </form>"""
    return f"""<details class="ban-menu">
  <summary class="danger">Action ▾</summary>
  <div class="ban-options">
    {_ban_btn(ip, 900,  "Ban 15 min")}
    {_ban_btn(ip, 3600, "Ban 1 hour")}
    {_ban_btn(ip, 86400,"Ban 24 hours")}
    <form hx-post="/block" hx-swap="none" class="inline">
      <input type="hidden" name="ip" value="{ip}">
      <button class="danger">Block (permanent)</button>
    </form>
    <form hx-post="/whitelist" hx-swap="none" class="inline">
      <input type="hidden" name="ip" value="{ip}">
      <button class="good">Allow</button>
    </form>
  </div>
</details>"""


def _ban_btn(ip: str, ttl: int, label: str) -> str:
    return f"""<form hx-post="/ban" hx-swap="none" class="inline">
  <input type="hidden" name="ip" value="{ip}">
  <input type="hidden" name="ttl" value="{ttl}">
  <button class="danger">{label}</button>
</form>"""


def _render_alerts(cur_alerts: list[dict]) -> str:
    if not cur_alerts:
        return '<p class="muted">Quiet. No active alerts.</p>'
    body = []
    for a in cur_alerts:
        body.append(f"""
<li class="alert-{a['kind']}">
  <span class="kind">{a['kind'].replace('_', ' ')}</span>
  <span class="key">{html.escape(a['key'])}</span>
  <span class="detail">{html.escape(a['detail'])}</span>
  <span class="muted at">{iso(a['at'])}</span>
</li>""")
    return f"<ul class='alerts'>{''.join(body)}</ul>"


def _render_feed(feed: list[dict]) -> str:
    if not feed:
        return '<p class="muted">Feed is empty.</p>'
    # Compute current ban/allow/block status per row so the action menu in
    # each feed entry can offer the right next step (Unban vs Ban, etc.) —
    # makes Live tab fully interoperable with IPs/Bans tabs.
    n = now()
    with state_lock:
        ban_map = dict(bans)
        allow = dict(allowlist)
        block = dict(blocklist)
    body = []
    for e in feed:
        cls = "ok" if e["success"] else "fail"
        ip = e["ip"]
        status, status_label = _classify(ip, ban_map, allow, block, n)
        action_cell = _render_action_cell({
            "ip": ip,
            "status": status,
            "status_label": status_label,
        })
        body.append(f"""
<tr class="feed-{cls}">
  <td class="ts">{iso(e["ts"])}</td>
  <td class="verdict">{'OK  ' if e["success"] else 'FAIL'}</td>
  <td class="ip">{html.escape(ip)}</td>
  <td>{html.escape(e["username"])}</td>
  <td class="ua">{html.escape(_short_ua(e["user_agent"]))}</td>
  <td class="muted">{html.escape(e.get("failure_reason") or "")}</td>
  <td class="actions">{action_cell}</td>
</tr>""")
    return f"<table class='feed'><tbody>{''.join(body)}</tbody></table>"


def _render_bans_table(cur_bans: list, n: float) -> str:
    if not cur_bans:
        return '<p class="muted">No active bans. Ban an IP from the IPs tab to see it here.</p>'
    body = []
    for ip, entry in cur_bans:
        exp = entry["expires_at"]
        remaining = int(exp - n)
        reason = entry.get("reason") or ""
        body.append(f"""
<tr>
  <td class="ip">{html.escape(ip)}</td>
  <td class="muted">{html.escape(geolocate(ip)[2])}</td>
  <td class="ts">until {iso(exp)} <span class="muted">({_fmt_remaining(remaining)})</span></td>
  <td class="muted">{html.escape(reason)}</td>
  <td class="actions">
    <form hx-post="/unban" hx-swap="none" class="inline">
      <input type="hidden" name="ip" value="{html.escape(ip)}">
      <button class="ghost">Unban</button>
    </form>
  </td>
</tr>""")
    return f"""<table class="agg">
<thead><tr><th>IP</th><th>Location</th><th>Expires</th><th>Reason</th><th></th></tr></thead>
<tbody>{''.join(body)}</tbody></table>"""


def _render_allow_table(cur_allow: list) -> str:
    if not cur_allow:
        return '<p class="muted">No allowlisted IPs.</p>'
    body = []
    for ip, entry in cur_allow:
        reason = entry.get("reason") or ""
        body.append(f"""
<tr>
  <td class="ip">{html.escape(ip)}</td>
  <td class="muted">{html.escape(geolocate(ip)[2])}</td>
  <td class="muted">{html.escape(reason)}</td>
  <td class="actions">
    <form hx-post="/unallow" hx-swap="none" class="inline">
      <input type="hidden" name="ip" value="{html.escape(ip)}">
      <button class="ghost">Remove</button>
    </form>
  </td>
</tr>""")
    return f"""<table class="agg">
<thead><tr><th>IP</th><th>Location</th><th>Reason</th><th></th></tr></thead>
<tbody>{''.join(body)}</tbody></table>"""


def _render_block_table(cur_block: list) -> str:
    if not cur_block:
        return '<p class="muted">No blocklisted IPs.</p>'
    body = []
    for ip, entry in cur_block:
        reason = entry.get("reason") or ""
        body.append(f"""
<tr>
  <td class="ip">{html.escape(ip)}</td>
  <td class="muted">{html.escape(geolocate(ip)[2])}</td>
  <td class="muted">{html.escape(reason)}</td>
  <td class="actions">
    <form hx-post="/unblock" hx-swap="none" class="inline">
      <input type="hidden" name="ip" value="{html.escape(ip)}">
      <button class="ghost">Unblock</button>
    </form>
  </td>
</tr>""")
    return f"""<table class="agg">
<thead><tr><th>IP</th><th>Location</th><th>Reason</th><th></th></tr></thead>
<tbody>{''.join(body)}</tbody></table>"""


def _fmt_remaining(secs: int) -> str:
    if secs < 60:
        return f"{secs}s left"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s left"
    return f"{secs // 3600}h {(secs % 3600) // 60}m left"


def _short_ua(ua: str) -> str:
    if not ua:
        return ""
    if "curl" in ua:
        return "curl"
    if "python-requests" in ua:
        return "python-requests"
    if "Firefox" in ua:
        return "Firefox"
    if "Chrome" in ua:
        return "Chrome"
    if "Safari" in ua:
        return "Safari"
    return ua[:24]


MAP_JS = """
function setWindow(v) {
  // In-session cookie: same path/SameSite as the session cookie. NOT a
  // full-page reload — the server force-resets this to 5m on every GET /,
  // so reloading would just flip back to the default and confuse the user.
  // Instead we refresh the active panels in-place so the new window takes
  // effect immediately without losing the picker selection.
  var secure = (location.protocol === 'https:') ? '; Secure' : '';
  document.cookie = 'dashboard_window=' + encodeURIComponent(v) +
    '; path=/; max-age=' + (60 * 60 * 24 * 365) +
    '; SameSite=Lax' + secure;

  // Map view: kick the marker + side-feed fetches directly (they're not
  // HTMX-managed). Then nudge the HTMX-managed content panel to refetch
  // by firing a synthetic sse:update — same trigger the panels already
  // listen for, so no per-tab routing logic needed.
  if (document.querySelector('main').classList.contains('show-map')) {
    refreshMarkers();
    refreshSideFeed();
  }
  var content = document.getElementById('content');
  if (content && typeof htmx !== 'undefined') {
    htmx.trigger(content, 'sse:update');
  }
}

let _mapInstance = null;
let _markerLayer = null;
let _tileLayer = null;
let _lastMapRefresh = 0;
let _popupOpen = false;
let _currentStyle = 'carto_dark';

// Attribution strings required by tile licenses.
var _CARTO_ATTR = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>';
var _ESRI_ATTR = 'Tiles &copy; <a href="https://www.esri.com">Esri</a>';

var TILE_PROVIDERS = {
  carto_dark: {
    label: 'CARTO Dark',
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    opts: { subdomains: 'abcd', maxZoom: 19, detectRetina: true, attribution: _CARTO_ATTR },
  },
  carto_light: {
    label: 'CARTO Light',
    url: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
    opts: { subdomains: 'abcd', maxZoom: 19, detectRetina: true, attribution: _CARTO_ATTR },
  },
  carto_voyager: {
    label: 'CARTO Voyager',
    url: 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',
    opts: { subdomains: 'abcd', maxZoom: 19, detectRetina: true, attribution: _CARTO_ATTR },
  },
  opentopomap: {
    label: 'OpenTopoMap',
    url: 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
    opts: {
      subdomains: 'abc', maxZoom: 17,
      attribution: 'Map data: &copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>, SRTM | Style: <a href="https://opentopomap.org">OpenTopoMap</a> (CC-BY-SA)',
    },
  },
  esri_satellite: {
    label: 'ESRI Satellite',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    opts: { maxZoom: 19, attribution: _ESRI_ATTR },
  },
};

function setMapStyle(name) {
  if (!_mapInstance || !TILE_PROVIDERS[name]) return;
  if (_tileLayer) _mapInstance.removeLayer(_tileLayer);
  var p = TILE_PROVIDERS[name];
  _tileLayer = L.tileLayer(p.url, p.opts).addTo(_mapInstance);
  _currentStyle = name;
}

function _addStylePicker(map) {
  var ctl = L.control({ position: 'topright' });
  ctl.onAdd = function() {
    var div = L.DomUtil.create('div', 'leaflet-bar style-picker');
    var html = '';
    Object.keys(TILE_PROVIDERS).forEach(function(key) {
      var active = (key === _currentStyle) ? ' active' : '';
      html += '<button data-style="' + key + '" class="sp-btn' + active + '">' + TILE_PROVIDERS[key].label + '</button>';
    });
    div.innerHTML = html;
    L.DomEvent.disableClickPropagation(div);
    div.addEventListener('click', function(e) {
      var btn = e.target.closest('button');
      if (!btn) return;
      var style = btn.getAttribute('data-style');
      if (!style) return;
      setMapStyle(style);
      div.querySelectorAll('button').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
    });
    return div;
  };
  ctl.addTo(map);
}

function _addFullscreenControl(map) {
  var ctl = L.control({ position: 'topleft' });  // next to zoom +/- controls
  ctl.onAdd = function() {
    var div = L.DomUtil.create('div', 'leaflet-bar fs-control');
    div.innerHTML = '<a href="#" title="Toggle fullscreen">\\u26F6</a>';
    L.DomEvent.disableClickPropagation(div);
    div.querySelector('a').addEventListener('click', function(e) {
      e.preventDefault();
      var c = map.getContainer();
      if (document.fullscreenElement) {
        document.exitFullscreen();
      } else {
        c.requestFullscreen().catch(function() {});
      }
      setTimeout(function() { map.invalidateSize(); }, 200);
    });
    return div;
  };
  ctl.addTo(map);
}

function _setActive(btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

function showMap(btn) {
  _setActive(btn);
  document.querySelector('main').classList.add('show-map');
  if (!_mapInstance) {
    _mapInstance = L.map('login-map', {
      worldCopyJump: true,
      closePopupOnClick: false,  // popup buttons need clicks; map-click won't auto-close
      attributionControl: false, // disable default (bottomright); custom one below at bottomleft
    }).setView([30, 30], 2);
    L.control.attribution({ position: 'bottomleft', prefix: false }).addTo(_mapInstance);
    setMapStyle('carto_dark');
    _markerLayer = L.layerGroup().addTo(_mapInstance);
    _addStylePicker(_mapInstance);
    _addFullscreenControl(_mapInstance);
    _mapInstance.on('popupopen',  function() { _popupOpen = true;  });
    _mapInstance.on('popupclose', function() { _popupOpen = false; });
  }
  // Force Leaflet to recompute size now that container is visible.
  setTimeout(function() { _mapInstance.invalidateSize(); }, 50);
  refreshMarkers();
  refreshSideFeed();
}

function hideMap(btn) {
  _setActive(btn);
  document.querySelector('main').classList.remove('show-map');
}

function _escape(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

function _popupHtml(m) {
  var ipSafe = _escape(m.ip);
  return (
    '<b>' + ipSafe + '</b><br>' +
    _escape(m.label) + '<br>' +
    '<span style="color:#6cdb8c">OK ' + m.ok + '</span> &nbsp; ' +
    '<span style="color:#ff8a96">FAIL ' + m.fail + '</span><br>' +
    'last user: ' + _escape(m.user || '\\u2014') + '<br>' +
    'status: ' + _escape(m.status) +
    '<div class="popup-actions">' +
      '<button onclick="event.stopPropagation(); banFromPopup(\\'' + ipSafe + '\\', 900); return false;">Ban 15m</button>' +
      '<button onclick="event.stopPropagation(); banFromPopup(\\'' + ipSafe + '\\', 3600); return false;">1h</button>' +
      '<button onclick="event.stopPropagation(); banFromPopup(\\'' + ipSafe + '\\', 86400); return false;">24h</button>' +
      '<button onclick="event.stopPropagation(); whitelistFromPopup(\\'' + ipSafe + '\\'); return false;" class="good">Allow</button>' +
    '</div>'
  );
}

function banFromPopup(ip, ttl) {
  var fd = new FormData();
  fd.append('ip', ip);
  fd.append('ttl', String(ttl));
  fetch('/ban', { method: 'POST', body: fd }).then(function() {
    if (_mapInstance) _mapInstance.closePopup();
    refreshMarkers();
  });
}

function whitelistFromPopup(ip) {
  var fd = new FormData();
  fd.append('ip', ip);
  fetch('/whitelist', { method: 'POST', body: fd }).then(function() {
    if (_mapInstance) _mapInstance.closePopup();
    refreshMarkers();
  });
}

function refreshMarkers() {
  if (!_mapInstance || !_markerLayer) return;
  if (_popupOpen) return;  // don't clobber an open popup with a marker refresh
  _lastMapRefresh = Date.now();
  fetch('/api/map-markers').then(function(r) { return r.json(); }).then(function(data) {
    _markerLayer.clearLayers();
    // Rebuild the IP -> marker index so side-feed click-to-zoom can find
    // the right circle marker after every refresh tick.
    window._markersByIp = {};
    data.markers.forEach(function(m) {
      var radius = Math.max(7, Math.min(22, 6 + (m.ok + m.fail) * 1.5));
      var marker = L.circleMarker([m.lat, m.lng], {
        radius: radius,
        color: m.color,
        weight: 2,
        fillColor: m.color,
        fillOpacity: 0.45,
      }).bindPopup(_popupHtml(m)).addTo(_markerLayer);
      window._markersByIp[m.ip] = marker;
    });
    var stat = document.getElementById('map-stat');
    if (stat) stat.textContent = '(' + data.markers.length + ' unique IPs · last ' + data.window_label + ')';
  });
}

function focusMapOn(ip) {
  // Side-feed entries delegate to this on click. flyTo + openPopup the
  // existing circleMarker; no separate geo lookup needed. Silent no-op
  // when the IP isn't on the map (event outside the window, private IP,
  // etc.) — caller can widen the window picker if they need to see it.
  if (!_mapInstance) return;
  var m = (window._markersByIp || {})[ip];
  if (!m) return;
  _mapInstance.flyTo(m.getLatLng(), 15, {duration: 0.6});
  // openPopup races the flyTo animation if called immediately, so defer
  // just past the animation duration.
  setTimeout(function() { m.openPopup(); }, 650);
}

function refreshSideFeed() {
  fetch('/api/feed').then(function(r) { return r.json(); }).then(function(data) {
    var host = document.getElementById('feed-side');
    if (!host) return;
    if (!data.events.length) {
      host.innerHTML = '<p class="muted">No events. Click a scenario above.</p>';
    } else {
      var rows = data.events.map(function(e) {
        var verdict = e.success ? 'OK' : 'FAIL';
        var cls = e.success ? 'ok' : 'fail';
        var ipSafe = _escape(e.ip);
        return (
          '<div class="feed-row feed-' + cls + '" ' +
               'onclick="focusMapOn(\\'' + ipSafe + '\\')" ' +
               'title="Click to focus map on ' + ipSafe + '">' +
            '<span class="t">' + _escape(e.ts) + '</span>' +
            '<span class="v">' + verdict + '</span>' +
            '<span class="ip">' + ipSafe + '</span>' +
            '<span class="u">' + _escape(e.username) + '</span>' +
          '</div>'
        );
      }).join('');
      host.innerHTML = rows;
    }
    var stat = document.getElementById('feed-stat');
    if (stat) stat.textContent = '(' + data.total + ' buffered, newest first)';
  });
}

// SSE-driven refresh: only when map is visible, throttled to 1.5s max.
document.body.addEventListener('htmx:sseMessage', function(ev) {
  if (!ev.detail || ev.detail.type !== 'update') return;
  if (!document.querySelector('main').classList.contains('show-map')) return;
  if (Date.now() - _lastMapRefresh < 1500) return;
  refreshMarkers();
  refreshSideFeed();
});

// When the server renders the page with the Map tab already active (default
// landing), the show-map class is on <main> from the start but Leaflet hasn't
// been initialized yet — showMap() does that lazily. Find the active button
// and hand it off so initialization, marker fetch, and side-feed fetch all
// happen on first paint.
document.addEventListener('DOMContentLoaded', function() {
  if (document.querySelector('main').classList.contains('show-map')) {
    var activeBtn = document.querySelector('nav.tabs .tab.active');
    if (activeBtn) showMap(activeBtn);
  }
});
"""


CSS = """
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, BlinkMacSystemFont, "SF Mono", Menlo, monospace;
  background: #0b0d10; color: #e6e6e6; font-size: 13px;
}
header {
  background: #11151a; border-bottom: 1px solid #1f2730;
  padding: 12px 20px; display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 10;
}
.title { font-weight: 600; font-size: 15px; }
.tag {
  margin-left: 8px; background: #1a2027; color: #889;
  padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 500;
  display: inline-block; vertical-align: middle;
}
.tag-live { background: #14271a; color: #6cdb8c; }
.tag-warn { background: #3b2a00; color: #ffc14a; }
.tag-ghost { background: transparent; border: 1px solid #2a3340; color: #889; text-decoration: none; cursor: pointer; }
.tag-ghost:hover { background: #1c232c; color: #ccd; }
.subtitle {
  margin-left: 10px; color: #4a5260; font-size: 11px; font-weight: 400;
}
.scenarios { display: flex; gap: 8px; }
.header-controls { display: flex; gap: 10px; align-items: center; }
.window-picker {
  background: #1c232c; color: #e6e6e6;
  border: 1px solid #2a3340; border-radius: 4px;
  padding: 5px 8px; font-family: inherit; font-size: 12px; cursor: pointer;
}
.window-picker:hover { background: #242c37; border-color: #3a4757; }
.window-picker:focus { outline: none; border-color: #6cb2ff; }
button {
  background: #1c232c; color: #e6e6e6; border: 1px solid #2a3340;
  padding: 5px 12px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px;
}
button:hover { background: #242c37; border-color: #3a4757; }
button.danger { background: #2a1417; border-color: #5a262f; color: #ff8a96; }
button.danger:hover { background: #3a1d22; }
button.warn { background: #2a2414; border-color: #5a4a26; color: #ffc14a; }
button.good { background: #14271a; border-color: #275a35; color: #6cdb8c; }
button.ghost { background: transparent; border-color: #2a3340; color: #889; }

nav.tabs {
  display: flex; gap: 2px; padding: 0 20px;
  background: #0b0d10; border-bottom: 1px solid #1f2730;
  position: sticky; top: 53px; z-index: 9;
}
.tab {
  background: transparent; color: #889; border: 1px solid transparent;
  border-radius: 4px 4px 0 0; padding: 8px 18px;
  cursor: pointer; font-family: inherit; font-size: 13px;
  border-bottom: 2px solid transparent;
}
.tab:hover { color: #ccd; background: #11151a; }
.tab.active {
  color: #e6e6e6; background: #11151a;
  border-bottom-color: #6cb2ff;
}

main { padding: 16px 20px; }
/* Tab toggle: default = #content visible, #map-wrapper hidden.
   When .show-map is on <main>, swap them. Class lives on a parent that
   HTMX swaps never touch, so visibility stays correct across SSE refreshes. */
#map-wrapper { display: none; }
main.show-map #content { display: none; }
main.show-map #map-wrapper { display: block; }
.panel {
  background: #11151a; border: 1px solid #1f2730;
  border-radius: 6px; padding: 14px 16px; margin-bottom: 14px;
}
.panel h2 {
  margin: 0 0 10px 0; font-size: 13px; font-weight: 600;
  color: #ccd; text-transform: uppercase; letter-spacing: 0.5px;
}
.muted { color: #687080; font-weight: 400; }

table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #1a2027; }
th { color: #889; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }
td.num { font-variant-numeric: tabular-nums; text-align: right; width: 50px; }
td.ok { color: #6cdb8c; }
td.fail { color: #ff8a96; font-weight: 600; }
td.ts, td.ua { color: #889; font-size: 12px; }
td.ip { font-weight: 600; }
td.actions { text-align: right; }
td.verdict { font-weight: 600; width: 50px; font-family: "SF Mono", monospace; }

.feed-ok td.verdict { color: #6cdb8c; }
.feed-fail td.verdict { color: #ff8a96; }
.feed-fail { background: rgba(255, 138, 150, 0.04); }

.row-hot { background: rgba(255, 138, 150, 0.06); }
.row-banned { background: rgba(255, 138, 150, 0.12); opacity: 0.85; }
.row-allow { background: rgba(108, 219, 140, 0.06); }

.ban-menu { display: inline-block; position: relative; }
.ban-menu summary {
  list-style: none; cursor: pointer; user-select: none;
  background: #2a1417; border: 1px solid #5a262f; color: #ff8a96;
  padding: 4px 10px; border-radius: 4px; font-size: 12px;
}
.ban-menu summary::-webkit-details-marker { display: none; }
.ban-menu[open] .ban-options {
  position: absolute; right: 0; top: 28px; background: #11151a;
  border: 1px solid #2a3340; border-radius: 4px; padding: 6px; z-index: 5;
  display: flex; flex-direction: column; gap: 4px; min-width: 110px;
}
form.inline { display: inline; margin: 0; }

.alerts { list-style: none; padding: 0; margin: 0; }
.alerts li {
  display: grid; grid-template-columns: 130px 220px 1fr 80px;
  gap: 12px; padding: 6px 8px; border-bottom: 1px solid #1a2027; align-items: center;
}
.alerts li:last-child { border-bottom: none; }
.alerts .kind {
  text-transform: uppercase; font-size: 11px; font-weight: 600; letter-spacing: 0.5px;
  padding: 2px 6px; border-radius: 3px;
}
.alert-brute_force .kind   { background: #2a1417; color: #ff8a96; }
.alert-cred_stuffing .kind { background: #2a2414; color: #ffc14a; }
.alert-geo_anomaly .kind   { background: #14202a; color: #6cb2ff; }
.alerts .key { font-weight: 600; }
.alerts .detail { color: #aab; font-size: 12px; }
.alerts .at { text-align: right; font-size: 11px; }

body { overflow: hidden; }  /* page must fit viewport; no scroll */

.map-split {
  display: grid; grid-template-columns: minmax(0, 7fr) minmax(0, 3fr);
  gap: 14px; align-items: stretch;
  height: calc(100vh - 130px);
}
.map-split > .panel { margin-bottom: 0; display: flex; flex-direction: column; min-width: 0; }
.map-panel { padding-bottom: 12px; }
.map-legend {
  display: flex; gap: 14px; margin-bottom: 10px;
  font-size: 12px; color: #aab; align-items: center; flex-wrap: wrap;
}
.map-legend .dot {
  display: inline-block; width: 10px; height: 10px; border-radius: 50%;
  margin: 0 4px 0 0; vertical-align: middle;
}
#login-map {
  flex: 1 1 auto; min-height: 300px;
  border-radius: 4px; background: #1a2027;
}
.leaflet-container { background: #1a2027 !important; }
/* Map style picker (custom Leaflet control, top-right) */
.style-picker {
  background: rgba(17, 21, 26, 0.92) !important;
  border: 1px solid #2a3340 !important;
  border-radius: 6px !important;
  padding: 3px !important;
  display: flex; flex-direction: column; gap: 1px;
  min-width: 160px;
  max-height: calc(100vh - 200px);
  overflow-y: auto;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
}
.style-picker .sp-btn {
  background: transparent; color: #aab; border: none;
  padding: 4px 9px; cursor: pointer; font-size: 11px;
  border-radius: 3px; text-align: left;
  font-family: inherit; line-height: 1.3;
  white-space: nowrap;
}
.style-picker .sp-btn:hover { background: rgba(255,255,255,0.05); color: #e6e6e6; }
.style-picker .sp-btn.active {
  background: rgba(108, 178, 255, 0.15); color: #6cb2ff; font-weight: 600;
}

/* Fullscreen toggle (separate Leaflet control, sits below style picker) */
.fs-control {
  background: rgba(17, 21, 26, 0.92) !important;
  border: 1px solid #2a3340 !important;
  border-radius: 6px !important;
  margin-top: 6px !important;
  width: auto !important;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
  overflow: hidden;
}
.fs-control a {
  display: block; width: 30px; height: 30px;
  line-height: 30px; text-align: center;
  color: #aab; text-decoration: none; font-size: 16px;
  background: transparent;
}
.fs-control a:hover { background: rgba(255,255,255,0.05); color: #e6e6e6; }

/* Dark-themed attribution (bottom-left corner of map) */
.leaflet-control-attribution {
  background: rgba(17, 21, 26, 0.85) !important;
  color: #687080 !important;
  border: 1px solid #1f2730 !important;
  border-radius: 3px !important;
  font-size: 10px !important;
  padding: 2px 6px !important;
  margin: 4px !important;
}
.leaflet-control-attribution a { color: #6cb2ff !important; }
.leaflet-control-attribution a:hover { color: #8cc3ff !important; }

.leaflet-popup-content-wrapper { background: #11151a; color: #e6e6e6; border-radius: 4px; }
.leaflet-popup-tip { background: #11151a; }
.leaflet-popup-content { font-size: 12px; margin: 10px 12px; }
.leaflet-popup-content b { color: #ffc14a; }
.popup-actions { margin-top: 10px; display: flex; gap: 4px; flex-wrap: wrap; }
.popup-actions button {
  background: #2a1417; border: 1px solid #5a262f; color: #ff8a96;
  padding: 4px 8px; border-radius: 3px; font-size: 11px; cursor: pointer;
  font-family: inherit;
}
.popup-actions button.good { background: #14271a; border-color: #275a35; color: #6cdb8c; }

.side-feed-panel { overflow: hidden; }
#feed-side {
  flex: 1 1 auto;
  overflow: hidden;   /* per spec: older records disappear, no scroll */
  display: flex; flex-direction: column;
}
.feed-row {
  display: grid;
  grid-template-columns: 58px 38px 110px 1fr;
  column-gap: 8px; align-items: center;
  padding: 4px 8px; border-bottom: 1px solid #1a2027;
  font-size: 11px; line-height: 1.4; flex: 0 0 auto;
  white-space: nowrap;
  cursor: pointer;
  transition: background-color 0.1s ease;
}
.feed-row:hover { background: rgba(108, 178, 255, 0.08); }
.feed-row > * { overflow: hidden; text-overflow: ellipsis; }
.feed-row .t { color: #687080; font-variant-numeric: tabular-nums; }
.feed-row .v { font-weight: 600; }
.feed-row .ip { color: #ccd; font-weight: 500; }
.feed-row .u { color: #aab; }
.feed-ok .v { color: #6cdb8c; }
.feed-fail .v { color: #ff8a96; }
.feed-fail { background: rgba(255, 138, 150, 0.04); }
"""


# ---------- scenario player --------------------------------------------------
_scenario_lock = threading.Lock()
_active_scenarios: list[threading.Thread] = []


def play_scenario(name: str) -> bool:
    if name not in SCENARIOS:
        return False
    log(f"play scenario: {name}")
    t = threading.Thread(target=_play_thread, args=(name,), daemon=True)
    with _scenario_lock:
        _active_scenarios.append(t)
    t.start()
    return True


def _play_thread(name: str) -> None:
    for delay_ms, ev in SCENARIOS[name]:
        time.sleep(delay_ms / 1000.0)
        ingest_event(ev)


def clear_state() -> None:
    """Wipes the live feed buffer + alert ring. IP rules are server state —
    we do NOT touch them from /scenario/clear; they're refreshed from tms-auth
    on the next polling tick."""
    with state_lock:
        events.clear()
        alerts.clear()
    log("event buffer cleared")
    broadcast()


# ---------- ip-access rule sync (tms-auth) -----------------------------------
def _to_unix(iso_str: str) -> float:
    if not iso_str:
        return 0.0
    s = iso_str.replace("Z", "+00:00")
    try:
        from datetime import datetime
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _apply_rule_to_local(entry: dict) -> None:
    """Mutate local state from a GraphQL rule object. Caller holds state_lock."""
    ip = entry.get("ip")
    if not ip:
        return
    rule_id = entry.get("id")
    reason = entry.get("reason") or ""
    list_type = (entry.get("listType") or "").upper()
    if list_type == "ALLOW":
        allowlist[ip] = {"rule_id": rule_id, "reason": reason}
    elif list_type == "BLOCK":
        blocklist[ip] = {"rule_id": rule_id, "reason": reason}
    elif list_type == "BAN":
        bans[ip] = {
            "rule_id": rule_id,
            "reason": reason,
            "expires_at": _to_unix(entry.get("expiresAt") or ""),
        }


def hydrate_rules_from_auth() -> tuple[bool, str]:
    """Pull all three lists from tms-auth. Returns (ok, error_msg)."""
    if not graphql_client.auth_configured():
        return False, "AUTH_JWT not set"
    try:
        allow_rules = graphql_client.list_rules("ALLOW")
        block_rules = graphql_client.list_rules("BLOCK")
        ban_rules = graphql_client.list_rules("BAN")
    except graphql_client.GraphQLError as e:
        return False, str(e)
    with state_lock:
        allowlist.clear()
        blocklist.clear()
        bans.clear()
        for r in allow_rules:
            _apply_rule_to_local(r)
        for r in block_rules:
            _apply_rule_to_local(r)
        for r in ban_rules:
            _apply_rule_to_local(r)
    return True, ""


def _rule_sync_loop() -> None:
    """Pull ipAccessRules every RULES_REFRESH_S seconds. Short-polls every 5s
    while no JWT is available (e.g., fresh boot, no env AUTH_JWT, nobody
    signed in yet) and switches to the normal interval once an operator has
    signed in. Logs only on state transitions so the line doesn't spam every
    tick of the no-JWT loop."""
    last_log_state: Optional[str] = None  # "no_jwt", "ok", or last error msg
    while True:
        if not graphql_client.auth_configured():
            if last_log_state != "no_jwt":
                log("rule sync waiting — no JWT yet (will kick in on first signin)")
                last_log_state = "no_jwt"
            time.sleep(5)
            continue
        ok, err = hydrate_rules_from_auth()
        auth_status["last_refresh"] = now()
        auth_status["ok"] = ok
        auth_status["error"] = "" if ok else err
        if ok:
            if last_log_state != "ok":
                log("rule sync ok — hydrating Bans/Allowlist/Blocklist from tms-auth")
                last_log_state = "ok"
            broadcast()
        else:
            if last_log_state != err:
                log(f"rule sync failed: {err}")
                last_log_state = err
        time.sleep(RULES_REFRESH_S)


# ---------- signin page ------------------------------------------------------
SIGNIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in — Login Monitor</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #0b0d10; color: #e6e6e6; font-size: 13px;
  font-family: -apple-system, BlinkMacSystemFont, "SF Mono", Menlo, monospace;
}
.card {
  background: #11151a; border: 1px solid #1f2730; border-radius: 6px;
  padding: 28px 32px; width: 320px;
}
h1 { font-size: 15px; font-weight: 600; margin: 0 0 4px 0; }
.sub { color: #687080; font-size: 12px; margin-bottom: 18px; }
label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px;
        color: #889; margin: 12px 0 4px 0; }
input {
  width: 100%; padding: 8px 10px; background: #0b0d10; color: #e6e6e6;
  border: 1px solid #2a3340; border-radius: 4px; font-family: inherit; font-size: 13px;
}
input:focus { outline: none; border-color: #6cb2ff; }
button {
  width: 100%; margin-top: 18px; padding: 9px 12px; background: #1c232c;
  color: #e6e6e6; border: 1px solid #2a3340; border-radius: 4px;
  cursor: pointer; font-family: inherit; font-size: 13px;
}
button:hover { background: #242c37; border-color: #3a4757; }
.err { color: #ff8a96; background: rgba(255,138,150,0.06); border: 1px solid #5a262f;
       padding: 8px 10px; border-radius: 4px; margin-bottom: 12px; font-size: 12px; }
</style>
</head>
<body>
<form class="card" method="POST" action="/signin">
  <h1>Login Monitor</h1>
  <div class="sub">TMS360 security dashboard · super_admin only</div>
  __ERR__
  <label for="email">Email</label>
  <input id="email" type="email" name="email" autocomplete="email" autofocus required>
  <label for="password">Password</label>
  <input id="password" type="password" name="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
"""


def render_signin(error: str = "") -> str:
    err_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    return SIGNIN_HTML.replace("__ERR__", err_html)


# ---------- HTTP handler -----------------------------------------------------
# Paths reachable without a session cookie. Everything else 302s to /signin
# (for HTML) or 401s (for partial/api/SSE) when the cookie is missing/expired.
PUBLIC_PATHS = frozenset({"/signin", "/logout"})


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet the noisy default access log
        pass

    def _send(self, status: int, body: str, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_with_cookie(self, status: int, body: str, set_cookie: str,
                          ctype: str = "text/html; charset=utf-8") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _form(self) -> dict[str, str]:
        ln = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(ln).decode() if ln else ""
        parsed = parse_qs(raw)
        return {k: v[0] for k, v in parsed.items()}

    def _session(self):
        """Return {jwt, email, exp} for the signed-in operator, or None."""
        return auth_session.session_from_request_cookies(self.headers.get("Cookie"))

    def _window_s(self) -> int:
        """Read the user-chosen time window from the dashboard_window cookie.
        Clamped to [WINDOW_MIN_S, WINDOW_MAX_S]; falls back to DEFAULT_WINDOW_S
        for missing/garbage values so a bad cookie can't break the UI."""
        cookies = auth_session.parse_cookie_header(self.headers.get("Cookie"))
        raw = cookies.get(WINDOW_COOKIE, "")
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return DEFAULT_WINDOW_S
        if n < WINDOW_MIN_S or n > WINDOW_MAX_S:
            return DEFAULT_WINDOW_S
        return n

    def _client_ip(self) -> str:
        """Originating client IP. Railway / any reverse proxy puts the real
        client first in X-Forwarded-For; fall back to the socket peer when
        the header is missing (local dev, direct connections)."""
        fwd = self.headers.get("X-Forwarded-For") or ""
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def _redirect(self, location: str, set_cookie: str = "") -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _gate(self, path: str) -> bool:
        """Return True if the request may proceed. False = already responded."""
        if path in PUBLIC_PATHS:
            return True
        session = self._session()
        if session:
            # Remember the JWT so the background hydration loop can use it
            graphql_client.remember_session_jwt(session["jwt"])
            return True
        # Partial/api/SSE callers can't follow a redirect well; 401 cleanly.
        if path.startswith(("/partials/", "/api/", "/events")):
            self._send(401, "not signed in", "text/plain")
            return False
        self._redirect("/signin")
        return False

    def do_GET(self):
        path = urlparse(self.path).path
        if not self._gate(path):
            return
        if path == "/signin":
            # Already-signed-in users skip the form
            if self._session():
                return self._redirect("/")
            return self._send(200, render_signin())
        if path == "/logout":
            return self._redirect("/signin", set_cookie=auth_session.clear_cookie())
        if path == "/":
            # Full page loads always start on the default (5 min) window,
            # regardless of what the cookie remembered. Two reasons:
            # (a) avoid a heavy 24h replay aggregation on every refresh;
            # (b) make the dashboard's "first impression" predictable.
            # In-session refreshes (HTMX partials, /api/*) keep honoring
            # the cookie so user dropdown picks still work without reload.
            secure = "" if COOKIE_INSECURE else "; Secure"
            return self._send_with_cookie(
                200,
                render_page(self._session(), DEFAULT_WINDOW_S),
                f"{WINDOW_COOKIE}={DEFAULT_WINDOW_S}; Path=/; Max-Age={365*24*3600}; SameSite=Lax{secure}",
            )
        if path == "/partials/ips":
            return self._send(200, render_ips_panel(self._window_s()))
        if path == "/partials/alerts":
            return self._send(200, render_alerts_panel())
        if path == "/partials/live":
            return self._send(200, render_live_panel())
        if path == "/api/map-markers":
            return self._send(200, map_markers_json(self._window_s()), "application/json")
        if path == "/api/feed":
            return self._send(200, feed_json(), "application/json")
        if path == "/partials/bans":
            return self._send(200, render_bans_panel())
        if path == "/events":
            return self._sse()
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._gate(path):
            return

        if path == "/signin":
            client_ip = self._client_ip()
            wait = auth_session.check_signin_rate(client_ip)
            if wait > 0:
                log(f"[signin] rate-limited {client_ip} ({wait}s remaining)")
                msg = (
                    f"Too many sign-in attempts from your IP. "
                    f"Try again in {wait} seconds."
                )
                body = render_signin(msg).encode()
                self.send_response(429)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Retry-After", str(wait))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            # Stamp BEFORE the auth round-trip so a slow tms-auth can't let a
            # concurrent second request slip past the gate.
            auth_session.record_signin_attempt(client_ip)

            form = self._form()
            email = (form.get("email") or "").strip()
            password = form.get("password") or ""
            try:
                jwt, payload = auth_session.signin(email, password)
            except auth_session.SigninError as e:
                log(f"[signin] failed for {email!r} from {client_ip}: {e}")
                return self._send(401, render_signin(str(e)))
            graphql_client.remember_session_jwt(jwt)
            log(f"[signin] {email} from {client_ip}")
            return self._redirect(
                "/",
                set_cookie=auth_session.cookie_for(
                    jwt,
                    auth_session.jwt_exp_unix(payload),
                    secure=not COOKIE_INSECURE,
                ),
            )

        if path.startswith("/scenario/"):
            if not ENABLE_SCENARIOS:
                return self._send(404, "scenarios disabled", "text/plain")
            name = path.split("/", 2)[2]
            if name == "clear":
                clear_state()
                return self._send(204, "")
            if play_scenario(name):
                return self._send(204, "")
            return self._send(404, "unknown scenario", "text/plain")

        session = self._session()  # gate ensured this is not None
        op_jwt = session["jwt"]
        op_email = session["email"]
        op_reason = f"via security dashboard ({op_email})"

        if path == "/ban":
            form = self._form()
            ip = form.get("ip", "").strip()
            try:
                ttl = int(form.get("ttl", "0"))
            except ValueError:
                ttl = 0
            if not ip or ttl <= 0:
                return self._send(400, "bad ban payload", "text/plain")
            return self._mutate(
                action="ban",
                ip=ip,
                call=lambda: graphql_client.ban(ip, ttl, op_reason, jwt=op_jwt),
                local=lambda rule: bans.__setitem__(ip, {
                    "rule_id": (rule or {}).get("id"),
                    "reason": op_reason,
                    "expires_at": _to_unix((rule or {}).get("expiresAt") or "") or (now() + ttl),
                }),
            )

        if path == "/unban":
            form = self._form()
            ip = form.get("ip", "").strip()
            return self._mutate_remove(ip, bans, op_jwt)

        if path == "/whitelist":
            form = self._form()
            ip = form.get("ip", "").strip()
            return self._mutate(
                action="allow",
                ip=ip,
                call=lambda: graphql_client.add_allow(ip, op_reason, jwt=op_jwt),
                local=lambda rule: allowlist.__setitem__(ip, {
                    "rule_id": (rule or {}).get("id"),
                    "reason": op_reason,
                }),
            )

        if path == "/unallow":
            form = self._form()
            ip = form.get("ip", "").strip()
            return self._mutate_remove(ip, allowlist, op_jwt)

        if path == "/block":
            form = self._form()
            ip = form.get("ip", "").strip()
            return self._mutate(
                action="block",
                ip=ip,
                call=lambda: graphql_client.add_block(ip, op_reason, jwt=op_jwt),
                local=lambda rule: blocklist.__setitem__(ip, {
                    "rule_id": (rule or {}).get("id"),
                    "reason": op_reason,
                }),
            )

        if path == "/unblock":
            form = self._form()
            ip = form.get("ip", "").strip()
            return self._mutate_remove(ip, blocklist, op_jwt)

        return self._send(404, "not found", "text/plain")

    # ---------- mutation helpers ------------------------------------------
    def _mutate(self, *, action: str, ip: str, call, local) -> None:
        """Run a GraphQL mutation. The session's JWT is captured by `call`'s
        closure; we attempt it whenever a JWT is in scope, otherwise fall back
        to local-only state (kept for env-var / no-auth dev mode)."""
        if not ip:
            return self._send(400, "missing ip", "text/plain")
        rule = None
        sess = self._session()
        if sess or graphql_client.auth_configured():
            try:
                rule = call()
            except graphql_client.GraphQLError as e:
                log(f"[{action}] graphql error for {ip}: {e}")
                return self._send(502, f"auth service error: {e}", "text/plain")
        with state_lock:
            local(rule)
        log(f"[{action}] {ip} (rule_id={(rule or {}).get('id', 'local-only')})")
        broadcast()
        return self._send(204, "")

    def _mutate_remove(self, ip: str, target: dict, jwt: str = "") -> None:
        """Remove `ip` from the given local table; call removeIPRule when configured."""
        if not ip:
            return self._send(400, "missing ip", "text/plain")
        with state_lock:
            entry = target.get(ip)
        if not entry:
            # Nothing to do locally; surface 204 so UI doesn't show an error
            return self._send(204, "")
        rule_id = entry.get("rule_id")
        if rule_id and graphql_client.auth_configured(jwt=jwt):
            try:
                graphql_client.remove_rule(rule_id, jwt=jwt or None)
            except graphql_client.GraphQLError as e:
                log(f"[remove] graphql error for {ip}: {e}")
                return self._send(502, f"auth service error: {e}", "text/plain")
        with state_lock:
            target.pop(ip, None)
        log(f"[remove] {ip} (rule_id={rule_id or 'local-only'})")
        broadcast()
        return self._send(204, "")

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return
        q: queue.Queue = queue.Queue(maxsize=200)
        with state_lock:
            sse_subs.append(q)
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                except queue.Empty:
                    msg = ": keepalive\n\n"
                try:
                    self.wfile.write(msg.encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
        finally:
            with state_lock:
                if q in sse_subs:
                    sse_subs.remove(q)


# ---------- bans expiry sweeper ---------------------------------------------
def ban_sweeper():
    """Best-effort local TTL — tms-auth is the source of truth, but we want
    the UI to drop expired bans without waiting for the next 30s rule sync."""
    while True:
        time.sleep(5)
        n = now()
        dirty = False
        with state_lock:
            expired = [ip for ip, entry in bans.items() if entry["expires_at"] <= n]
            for ip in expired:
                bans.pop(ip, None)
                dirty = True
        if dirty:
            log(f"ban expired: {expired}")
            broadcast()


# ---------- main -------------------------------------------------------------
def main():
    log(f"login-dashboard starting on :{PORT}")
    log(f"  ENABLE_SCENARIOS={ENABLE_SCENARIOS}")
    log(f"  kafka configured: {kafka_consumer.kafka_configured()}")
    log(f"  auth configured: {graphql_client.auth_configured()}")

    threading.Thread(target=ban_sweeper, daemon=True).start()
    kafka_consumer.start(ingest_event)
    # Always start rule-sync — it self-gates on JWT availability and short-polls
    # until an operator signs in. This way the Bans tab hydrates as soon as the
    # first signin happens, instead of staying empty until a process restart.
    threading.Thread(target=_rule_sync_loop, daemon=True, name="rule-sync").start()

    server = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    log(f"serving at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
