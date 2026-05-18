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

## What's NOT shipped

- No alert rules beyond the three already in `main.py` (brute_force,
  cred_stuffing, geo_anomaly). Tuning thresholds happens in code.
- No JWT refresh loop — when a signed-in operator's token expires, they're
  bounced to /signin and sign in again. No silent re-auth.
- No persistence on the dashboard side — events are an in-memory ring buffer;
  Kafka is the source of truth, restart pulls fresh.

## Files

| File | Purpose |
|---|---|
| `main.py` | HTTP server, SSE, aggregator, alert rules, HTML render, session gate |
| `auth_session.py` | TMS360 signin proxy + JWT parsing + cookie helpers |
| `kafka_consumer.py` | Background thread that ingests `auth_events` |
| `graphql_client.py` | Minimal client for the 5 ipAccessRules operations |
| `geo.py` | MMDB lookup + scenario IP overrides |
| `scenarios.py` | Canned demo event streams (gated by `ENABLE_SCENARIOS=true`) |
| `scripts/setup_geolite2.sh` | MaxMind GeoLite2 fetcher (needs license key) |
| `scripts/setup_dbip.sh` | DB-IP City Lite fetcher (no signup, used by Dockerfile) |
| `Dockerfile` · `railway.json` | Railway deployment config |
