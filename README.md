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
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Then open <http://localhost:8000>.

## GeoIP setup (one-time)

The Map tab resolves IP → city using an offline MMDB file. Demo scenarios
use RFC5737 mock IPs that don't exist in any real GeoIP DB, so we keep a
hand-typed override table for them in `geo.py`; real production IPs go
through the MMDB.

Two options — pick one:

### Option A: DB-IP City Lite (no signup, fastest setup)

```sh
./scripts/setup_dbip.sh
```

Downloads `data/dbip-city-lite.mmdb` (~125 MB, gitignored, CC-BY-4.0).
Refreshed monthly — re-run on the 1st of any month to update.

### Option B: MaxMind GeoLite2-City (more accurate, needs free signup)

1. Sign up free at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a license key in your account portal
3. Drop the DB into `data/`:

   ```sh
   export MAXMIND_LICENSE_KEY=xxxxxxxxxxxxx
   ./scripts/setup_geolite2.sh
   ```

Writes `data/GeoLite2-City.mmdb` (~60 MB, gitignored). MaxMind refreshes
the DB ~twice a week.

`geo.py` prefers MaxMind if both files are present, otherwise uses DB-IP.
Dashboard runs fine with neither — real IPs fall back to "unknown
location" until one of the files is in place.

## Scenarios (click buttons in the header)

| Scenario | Story |
|---|---|
| `steady_state` | ~1 event/sec, mostly success — baseline |
| `brute_force` | One IP, 40 fails in 30s |
| `cred_stuffing` | 12 IPs, same 3 usernames |
| `geo_anomaly` | Token-theft pattern — same user from new IP |
| `clear` | Wipe buffer + bans + allowlist |

## Stack

Python 3.12. Only one runtime dependency: `maxminddb` (for GeoLite2 reads).

- `http.server.ThreadingHTTPServer`
- `threading` for SSE subscriber fan-out + scenario replay
- HTMX via CDN
- Leaflet via CDN (map tab)
- Inline HTML template in `main.py`

## Files

| File | Purpose |
|---|---|
| `main.py` | HTTP server, SSE, aggregator, alert rules, stubs, HTML |
| `geo.py` | GeoLite2-City lookup + IP_GEO demo overrides |
| `scenarios.py` | Pre-canned event streams |
| `scripts/setup_geolite2.sh` | Download GeoLite2-City.mmdb with your MaxMind license key |
| `scripts/setup_dbip.sh` | Download DB-IP City Lite MMDB (no signup) |

## What this is NOT

- ❌ Not connected to real auth — every event is fake
- ❌ Not deployed anywhere — runs locally
- ❌ No persistence — restart wipes state
- ❌ No user auth on the dashboard itself (localhost only)
