# login-dashboard (prototype)

Live login monitor for TMS360 auth. **Prototype only — fed by mock data.** No
auth integration yet; that conversation happens with Ravshan after the demo.

## What you see

- **Aggregates** — IP → success / fail counts in a 5-minute window
- **Alerts** — rule-based flags (brute-force, cred-stuffing, geo-anomaly)
- **Live feed** — every signin attempt, streamed via Server-Sent Events
- **Stub actions** — Ban (15m / 1h / 24h) + Whitelist buttons; these log to
  stdout and update in-memory state. No external call.

## Run

```sh
python3 main.py
```

Then open <http://localhost:8000>.

## Scenarios (click buttons in the header)

| Scenario | Story |
|---|---|
| `steady_state` | ~1 event/sec, mostly success — baseline |
| `brute_force` | One IP, 40 fails in 30s |
| `cred_stuffing` | 12 IPs, same 3 usernames |
| `geo_anomaly` | Token-theft pattern — same user from new IP |
| `clear` | Wipe buffer + bans + allowlist |

## Stack

Python 3.12 stdlib only. No `pip install`, no `requirements.txt`.

- `http.server.ThreadingHTTPServer`
- `threading` for SSE subscriber fan-out + scenario replay
- HTMX via CDN
- Inline HTML template in `main.py`

## Files

| File | Purpose |
|---|---|
| `main.py` | HTTP server, SSE, aggregator, alert rules, stubs, HTML |
| `scenarios.py` | Pre-canned event streams |

## What this is NOT

- ❌ Not connected to real auth — every event is fake
- ❌ Not deployed anywhere — runs locally
- ❌ No persistence — restart wipes state
- ❌ No user auth on the dashboard itself (localhost only)
