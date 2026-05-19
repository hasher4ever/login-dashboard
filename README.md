# login-dashboard

Live security monitor for TMS360 sign-in attempts. Consumes the
`auth_events` Kafka topic emitted by `tms-auth` and drives the IP
allow / block / ban controls through tms-auth's GraphQL API.

## Access

Operators sign in with their TMS360 credentials at `/signin`. The dashboard
proxies to `auth.tms360.io/api/auth/signin`, checks the returned JWT carries
`super_admin`, and sets it as an httpOnly session cookie. Every ban/allow/
block mutation is then performed *with that operator's own JWT* — so the
tms-auth audit log carries the real identity, not a shared service token.

## Modes

| Mode | Trigger | What you see |
|---|---|---|
| **Live** | `KAFKA_BROKERS` set + operator signed in | Real attempts stream in; ban/allow/block buttons hit tms-auth as the signed-in operator |
| **Local-only mutations** | No session, no `AUTH_JWT` | Buttons update in-memory state, no backend call (UI-test mode) |
| **Disconnected** | `KAFKA_BROKERS` unset | No event stream; pair with `ENABLE_SCENARIOS=true` for the canned demos |

The header pills show source state + signed-in operator email.

## Tabs

- **IPs** — per-IP aggregates over the last 5 min, sorted by failure count.
  Inline Ban (15 min / 1 h / 24 h) · Allow · Block (permanent).
- **Alerts** — rule firings: brute-force, credential-stuffing, geo-anomaly.
- **Live** — full event feed.
- **Map** — geo distribution + side-feed.
- **Bans** — active bans (with countdown) · blocklist · allowlist.

## Run locally

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Open <http://localhost:8000>. Without env vars the dashboard shows two warn
pills (`no KAFKA_BROKERS`, `no AUTH_JWT`) — set `ENABLE_SCENARIOS=true` to
get the canned demo buttons.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | HTTP listener |
| `ENABLE_SCENARIOS` | `false` | Show the brute_force / cred_stuffing / geo_anomaly demo buttons |
| `KAFKA_BROKERS` | _(unset)_ | Comma-separated bootstrap servers. Empty = disconnected. |
| `KAFKA_TOPIC` | `auth_events` | Topic to consume. |
| `KAFKA_GROUP_ID` | `login-dashboard` | Consumer group. |
| `KAFKA_SECURITY_PROTOCOL` | `PLAINTEXT` | `PLAINTEXT` \| `SASL_PLAINTEXT` \| `SASL_SSL` |
| `KAFKA_SASL_MECHANISM` | `PLAIN` | `PLAIN` \| `SCRAM-SHA-256` \| `SCRAM-SHA-512` (only when SASL) |
| `KAFKA_SASL_USERNAME` | _(unset)_ | (only when SASL) |
| `KAFKA_SASL_PASSWORD` | _(unset)_ | (only when SASL) |
| `AUTH_GRAPHQL_URL` | `https://api.tms360.io/` | tms-auth GraphQL endpoint. TMS360 serves GraphQL at `/`, not `/graphql`. |
| `AUTH_SIGNIN_URL` | `https://auth.tms360.io/api/auth/signin` | REST signin endpoint. Override only if it moves. |
| `AUTH_JWT` | _(unset)_ | Optional service token. If set, the rule-sync hydration loop runs even before any operator signs in. Mutations always prefer the signed-in operator's JWT. |
| `COOKIE_INSECURE` | `false` | Set to `true` only for local `http://` dev so the session cookie is set without the Secure flag. |
| `CLICKHOUSE_HOST` | _(unset)_ | ClickHouse hostname. Without it, the dashboard runs in deque-only mode — long windows (>5 min) show nothing. |
| `CLICKHOUSE_PORT` | `8123` | HTTP port. |
| `CLICKHOUSE_DATABASE` | `default` | Database that holds the `security_auth_events` table. |
| `CLICKHOUSE_USERNAME` | `default` | |
| `CLICKHOUSE_PASSWORD` | _(unset)_ | |
| `MAXMIND_LICENSE_KEY` | _(unset)_ | Enables the **geolite2** GeoIP backend. Free key from `https://www.maxmind.com/en/geolite2/signup`. Without it, only DB-IP (and IP2Location if configured) appear in the selector. |
| `IP2LOCATION_TOKEN` | _(unset)_ | Enables the **ip2location** GeoIP backend. Free token from `https://lite.ip2location.com/`. |
| `GEO_DEFAULT_BACKEND` | `ensemble` | First-pick backend for new sessions. Operators override per-browser via the header selector (persisted in localStorage). |
| `GEO_REFRESH_DISABLED` | `false` | Set to `true` to stop the in-process refresher daemon. Useful for tests or when running fresh DBs in from a sidecar. |
| `GEO_REFRESH_INTERVAL_S` | `3600` | How often the daemon re-checks each backend's age. Each backend has its own staleness threshold matching the upstream cadence; this is just the polling interval. |

## Geolocation backends

The Map tab resolves every IP into `(lat, lng, label)` against one of three
free, **DB-only** (no runtime API call) geolocation databases. Pick the one
to use from the header dropdown (`geo: <name>`); the choice is persisted
per-browser in localStorage.

| Backend | Source | License | Format | Upstream cadence | Auth |
|---|---|---|---|---|---|
| `geolite2` | MaxMind GeoLite2-City | CC BY-SA 4.0 | MMDB | twice weekly (Tue / Fri) | needs `MAXMIND_LICENSE_KEY` |
| `dbip` | DB-IP City Lite | CC BY 4.0 | MMDB | monthly (1st) | none |
| `ip2location` | IP2Location LITE DB11 | CC BY-SA 4.0 | BIN | monthly (1st) | needs `IP2LOCATION_TOKEN` |
| `ensemble` | majority vote across whichever of the above are loaded | — | — | — | — |

`ensemble` mode runs every loaded backend, keys results by `(city, country)`,
and picks the answer ≥2 backends agree on. Ties break by precedence
`ip2location > dbip > geolite2` (their relative city-coverage ranking per
APNIC's measurement study). Total disagreement falls back to the same
precedence list.

DBs are refreshed in-process by `geo_refresh.py` — a daemon thread that
re-runs the per-backend setup script on the upstream's publishing cadence.
A successful refresh hot-reloads the reader and evicts cached lookups; no
process restart needed. Missing auth env vars cause that backend to be
skipped silently (the selector shows it as `(not loaded)`).

To check live status: `GET /api/geo-backends` (requires signin) returns
the load state, file mtime, and cadence of every backend.

## Auth-service contract (per DEV-660)

**Topic** `auth_events` — JSON payload per attempt:

```json
{
  "attempt_id": "uuid",
  "timestamp":  "2026-05-18T17:32:14.812Z",
  "success":    false,
  "email":      "victim@tms360.io",
  "user_id":    "uuid-or-null",
  "company_id": "uuid-or-null",
  "ip":         "203.0.113.7",
  "user_agent": "curl/8.4.0",
  "client_type": "web",
  "failure_reason": "invalid_credentials"
}
```

Failure reasons: `invalid_credentials`, `unverified_email`,
`inactive_account`, `ip_blocked`, `ip_banned`.

**GraphQL** — super_admin role, IP lists are global (not tenancy-scoped):

```graphql
query   ipAccessRules(listType: AccessListType!)   # ALLOW | BLOCK | BAN
mutation addIPToAllowlist(ip: String!, reason: String)
mutation addIPToBlocklist(ip: String!, reason: String)
mutation banIP(ip: String!, ttlSeconds: Int!, reason: String)
mutation removeIPRule(id: ID!)
```

Precedence enforced server-side: **allow > block > ban > continue**.
Re-banning extends TTL. Sign-in rejections return `ip_blocked` (HTTP 403) or
`ip_banned` (HTTP 429).

## Deploy to Railway

```sh
railway login
railway init                          # name the project login-dashboard
railway up                            # build from Dockerfile and deploy
```

Then set env vars in the Railway dashboard (`Variables` tab):
- `KAFKA_BROKERS` + SASL creds (paste from the cluster you share with tms-auth)
- `AUTH_JWT` (super_admin token; regenerate when it expires — there is no
  refresh loop on the dashboard side)
- `AUTH_GRAPHQL_URL` only if non-default

The included Dockerfile downloads a DB-IP City Lite MMDB at build time so the
Map tab works without runtime setup. If the download fails, real IPs fall
back to "unknown location" and everything else still works.

## Persistence

When `CLICKHOUSE_HOST` is set, every event is written to a `security_auth_events`
table (created idempotently on boot, `ReplacingMergeTree`, partitioned by
month, **TTL 90 days**). All UI read paths (IPs / Map / Live) query CH so
long windows work without depending on Kafka retention or the in-memory
buffer size. The in-memory deque shrinks to 1k events and is used only for
real-time alert rules (brute_force / cred_stuffing / geo_anomaly recompute
on every ingest — far too hot to hammer a DB).

If CH is unreachable, the dashboard degrades — not goes down — to deque-only:
the 5-minute view and alerts keep working, long-window queries return empty
until CH is back. Writes during the outage are dropped (we don't buffer
indefinitely); on recovery the Kafka replay path (`auto_offset_reset=earliest`)
fills CH from whatever Kafka still retains.

## What's NOT shipped

- No alert rules beyond the three already in `main.py` (brute_force,
  cred_stuffing, geo_anomaly). Tuning thresholds happens in code.
- No JWT refresh loop — when a signed-in operator's token expires, they're
  bounced to /signin and sign in again. No silent re-auth.
- No ClickHouse Kafka-engine + materialized view (phase 2 — would let
  ClickHouse subscribe to `auth_events` directly and the dashboard become
  a pure query layer, but requires CH admin to provision the engine tables).
- No pre-aggregated rollup tables — raw events only. Add rollups if long-
  window queries get slow.

## Files

| File | Purpose |
|---|---|
| `main.py` | HTTP server, SSE, aggregator, alert rules, HTML render, session gate |
| `auth_session.py` | TMS360 signin proxy + JWT parsing + cookie helpers |
| `kafka_consumer.py` | Background thread that ingests `auth_events` + batches inserts to CH |
| `event_store.py` | ClickHouse client: schema, batch insert, window queries |
| `graphql_client.py` | Minimal client for the 5 ipAccessRules operations |
| `geo.py` | MMDB lookup + scenario IP overrides |
| `scenarios.py` | Canned demo event streams (gated by `ENABLE_SCENARIOS=true`) |
| `scripts/setup_geolite2.sh` | MaxMind GeoLite2 fetcher (needs license key) |
| `scripts/setup_dbip.sh` | DB-IP City Lite fetcher (no signup, used by Dockerfile) |
| `Dockerfile` · `railway.json` | Railway deployment config |
