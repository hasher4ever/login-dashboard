"""
Session auth for the dashboard itself — operators sign in with their TMS360
credentials via tms-auth's REST signin, then the returned JWT is what's used
both to gate the dashboard UI AND to authorize the per-operator ban/allow/
block mutations. No shared service token; every action is attributable.

Cookie model:
- Cookie name: dashboard_session
- Value: the raw JWT (kept opaque to the browser via httpOnly)
- Attributes: httpOnly, Secure (auto-relaxed on http://), SameSite=Lax,
  Max-Age = remaining seconds until JWT `exp`.

Super-admin gate enforced client-side too (defence in depth — tms-auth is the
real bar). The signin handler refuses to set the cookie if the JWT doesn't
carry super_admin.
"""

import base64
import json
import os
import time
import urllib.error
import urllib.request
from typing import Optional


AUTH_SIGNIN_URL = os.environ.get("AUTH_SIGNIN_URL", "https://auth.tms360.io/api/auth/signin")
COOKIE_NAME = "dashboard_session"


class SigninError(RuntimeError):
    pass


# ---------- JWT helpers ------------------------------------------------------

def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def parse_jwt(token: str) -> dict:
    """Decode the payload section. No signature verification — tms-auth is the
    real guard on every mutation; we only need claims for UI gating."""
    try:
        _, payload_b64, _ = token.split(".", 2)
        return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as e:
        raise SigninError(f"malformed JWT: {e}") from e


def jwt_exp_unix(payload: dict) -> int:
    """exp is unix-seconds per RFC 7519. 0 if missing — treated as 'expires now'."""
    try:
        return int(payload.get("exp") or 0)
    except (TypeError, ValueError):
        return 0


def is_super_admin(payload: dict) -> bool:
    """Tolerant role check — TMS360's JWT field name has shifted before.

    Accepts any of: role / roles / userRole / user.role / userType, comparing
    as lowercase strings or list-membership."""
    needle = "super_admin"
    candidates = [
        payload.get("role"),
        payload.get("roles"),
        payload.get("userRole"),
        payload.get("userType"),
        (payload.get("user") or {}).get("role"),
        (payload.get("user") or {}).get("roles"),
    ]
    for c in candidates:
        if c is None:
            continue
        if isinstance(c, str) and c.lower() == needle:
            return True
        if isinstance(c, (list, tuple, set)) and any(
            isinstance(x, str) and x.lower() == needle for x in c
        ):
            return True
    return False


def email_of(payload: dict) -> str:
    return (
        payload.get("email")
        or (payload.get("user") or {}).get("email")
        or payload.get("sub")
        or "unknown@tms360.io"
    )


# ---------- signin -----------------------------------------------------------

def signin(email: str, password: str) -> tuple[str, dict]:
    """Returns (jwt, payload). Raises SigninError on bad creds, network
    failure, missing super_admin role, etc."""
    if not email or not password:
        raise SigninError("email and password required")

    body = json.dumps({"email": email, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        AUTH_SIGNIN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "login-dashboard",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        # tms-auth returns 401 / 403 for bad creds — surface a clean message
        if e.code in (400, 401, 403):
            raise SigninError("invalid email or password") from e
        raise SigninError(f"auth service returned HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise SigninError(f"auth service unreachable: {e.reason}") from e

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise SigninError(f"non-JSON response from auth service") from e

    # tms-auth has shifted field names over time — try the obvious candidates
    jwt = (
        parsed.get("accessToken")
        or parsed.get("access_token")
        or parsed.get("token")
        or (parsed.get("data") or {}).get("accessToken")
        or (parsed.get("data") or {}).get("access_token")
    )
    if not jwt or not isinstance(jwt, str):
        raise SigninError("auth response missing access token")

    payload = parse_jwt(jwt)
    if not is_super_admin(payload):
        raise SigninError(
            "this account is not super_admin — security dashboard requires super_admin role"
        )
    if jwt_exp_unix(payload) <= int(time.time()):
        raise SigninError("auth service returned an already-expired token")

    return jwt, payload


# ---------- cookie helpers ---------------------------------------------------

def cookie_for(jwt: str, exp_unix: int, secure: bool = True) -> str:
    """Build a Set-Cookie value. `secure` should be False only for plain-http
    local dev; httpOnly + SameSite=Lax always on."""
    max_age = max(0, exp_unix - int(time.time()))
    parts = [
        f"{COOKIE_NAME}={jwt}",
        f"Max-Age={max_age}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_cookie() -> str:
    return f"{COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"


def parse_cookie_header(header_value: Optional[str]) -> dict[str, str]:
    """Tolerant Cookie header parser — accepts the standard form
    `a=1; b=2; c=3`. Unknown shapes return what we managed to extract."""
    out: dict[str, str] = {}
    if not header_value:
        return out
    for pair in header_value.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, _, v = pair.partition("=")
        out[k.strip()] = v.strip()
    return out


def session_from_request_cookies(cookie_header: Optional[str]) -> Optional[dict]:
    """Return a session dict {jwt, email, exp} if the request carries a valid
    non-expired dashboard_session cookie, else None."""
    cookies = parse_cookie_header(cookie_header)
    jwt = cookies.get(COOKIE_NAME)
    if not jwt:
        return None
    try:
        payload = parse_jwt(jwt)
    except SigninError:
        return None
    exp = jwt_exp_unix(payload)
    if exp <= int(time.time()):
        return None
    if not is_super_admin(payload):
        return None
    return {"jwt": jwt, "email": email_of(payload), "exp": exp}
