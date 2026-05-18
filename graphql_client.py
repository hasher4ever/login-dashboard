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


def auth_configured() -> bool:
    return bool(_env("AUTH_JWT"))


class GraphQLError(RuntimeError):
    pass


def _post(query: str, variables: dict) -> dict:
    jwt = _env("AUTH_JWT")
    if not jwt:
        raise GraphQLError("AUTH_JWT not set — cannot call tms-auth")

    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    req = urllib.request.Request(
        AUTH_GRAPHQL_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {jwt}",
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


def list_rules(list_type: str) -> list[dict]:
    """list_type ∈ {ALLOW, BLOCK, BAN}. Schema names enforced by tms-auth."""
    data = _post(Q_LIST, {"listType": list_type})
    return data.get("ipAccessRules") or []


def add_allow(ip: str, reason: str = "") -> dict:
    return _post(M_ADD_ALLOW, {"ip": ip, "reason": reason}).get("addIPToAllowlist") or {}


def add_block(ip: str, reason: str = "") -> dict:
    return _post(M_ADD_BLOCK, {"ip": ip, "reason": reason}).get("addIPToBlocklist") or {}


def ban(ip: str, ttl_seconds: int, reason: str = "") -> dict:
    return _post(M_BAN, {"ip": ip, "ttl": ttl_seconds, "reason": reason}).get("banIP") or {}


def remove_rule(rule_id: str) -> bool:
    data = _post(M_REMOVE, {"id": rule_id})
    return bool(data.get("removeIPRule"))
