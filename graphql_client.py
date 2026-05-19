"""
Thin GraphQL client for tms-auth's IP-access-rule API (per DEV-660 delivery).

Operations (super_admin role required):
    query   ipAccessRules(listType: AccessListType!)
    mutation addIPToAllowlist(ip: String!, reason: String)
    mutation addIPToBlocklist(ip: String!, reason: String)
    mutation banIP(ip: String!, ttlSeconds: Int!, reason: String)
    mutation removeIPRule(id: ID!)

Configuration (env vars):
    AUTH_GRAPHQL_URL    GraphQL endpoint. TMS360 serves GraphQL at /, not /graphql.
                        Default: https://api.tms360.io/
    AUTH_JWT            super_admin JWT pasted as a Railway secret. No refresh
                        loop — when it expires, paste a new one and restart.

Error contract: per the TMS360 memory rule, GraphQL always returns HTTP 200;
verdicts come from body.errors / body.data. `_post()` returns the data dict on
success, raises GraphQLError on body.errors or transport failure.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Optional


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


AUTH_GRAPHQL_URL = _env("AUTH_GRAPHQL_URL", "https://api.tms360.io/")

# Latest JWT seen via a successful authenticated request. Used by the
# background ipAccessRules sync when no env-level service token is set —
# means the hydration loop kicks in once *any* operator has signed in.
_latest_session_jwt: Optional[str] = None


def remember_session_jwt(jwt: str) -> None:
    global _latest_session_jwt
    _latest_session_jwt = jwt


def _service_jwt() -> Optional[str]:
    return _env("AUTH_JWT") or _latest_session_jwt


def auth_configured(jwt: Optional[str] = None) -> bool:
    """True if the caller has a usable JWT (either passed explicitly, set as
    env var, or remembered from a recent operator session)."""
    return bool(jwt or _service_jwt())


class GraphQLError(RuntimeError):
    pass


def _post(query: str, variables: dict, jwt: Optional[str] = None) -> dict:
    use_jwt = jwt or _service_jwt()
    if not use_jwt:
        raise GraphQLError("no JWT — sign in to the dashboard first or set AUTH_JWT")

    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    req = urllib.request.Request(
        AUTH_GRAPHQL_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {use_jwt}",
            # Cloudflare's WAF (rule 1010) blocks the default Python-urllib
            # User-Agent on api.tms360.io. Set an explicit UA so we're not
            # on the bot signature list. Preferred path is still to point
            # AUTH_GRAPHQL_URL at apollo.railway.internal so this never
            # touches Cloudflare at all.
            "User-Agent": "tms360-login-dashboard/1.0 (+railway-internal)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise GraphQLError(f"http {e.code}: {e.read()[:300].decode('utf-8', 'replace')}") from e
    except urllib.error.URLError as e:
        raise GraphQLError(f"transport error: {e.reason}") from e

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise GraphQLError(f"non-JSON response: {raw[:200]!r}") from e

    if parsed.get("errors"):
        first = parsed["errors"][0]
        msg = first.get("message", "unknown GraphQL error")
        raise GraphQLError(msg)
    return parsed.get("data") or {}


# ---------- queries / mutations ----------------------------------------------

Q_LIST = """
query IpAccessRules($listType: AccessListType!) {
  ipAccessRules(listType: $listType) {
    id
    ip
    listType
    reason
    expiresAt
    createdAt
  }
}
"""

M_ADD_ALLOW = """
mutation AddAllow($ip: String!, $reason: String) {
  addIPToAllowlist(ip: $ip, reason: $reason) { id ip listType reason expiresAt }
}
"""

M_ADD_BLOCK = """
mutation AddBlock($ip: String!, $reason: String) {
  addIPToBlocklist(ip: $ip, reason: $reason) { id ip listType reason expiresAt }
}
"""

M_BAN = """
mutation Ban($ip: String!, $ttl: Int!, $reason: String) {
  banIP(ip: $ip, ttlSeconds: $ttl, reason: $reason) { id ip listType reason expiresAt }
}
"""

M_REMOVE = """
mutation Remove($id: ID!) {
  removeIPRule(id: $id)
}
"""


def list_rules(list_type: str, jwt: Optional[str] = None) -> list[dict]:
    """list_type ∈ {ALLOW, BLOCK, BAN}. Schema names enforced by tms-auth."""
    data = _post(Q_LIST, {"listType": list_type}, jwt=jwt)
    return data.get("ipAccessRules") or []


def add_allow(ip: str, reason: str = "", jwt: Optional[str] = None) -> dict:
    return _post(M_ADD_ALLOW, {"ip": ip, "reason": reason}, jwt=jwt).get("addIPToAllowlist") or {}


def add_block(ip: str, reason: str = "", jwt: Optional[str] = None) -> dict:
    return _post(M_ADD_BLOCK, {"ip": ip, "reason": reason}, jwt=jwt).get("addIPToBlocklist") or {}


def ban(ip: str, ttl_seconds: int, reason: str = "", jwt: Optional[str] = None) -> dict:
    return _post(M_BAN, {"ip": ip, "ttl": ttl_seconds, "reason": reason}, jwt=jwt).get("banIP") or {}


def remove_rule(rule_id: str, jwt: Optional[str] = None) -> bool:
    data = _post(M_REMOVE, {"id": rule_id}, jwt=jwt)
    return bool(data.get("removeIPRule"))
