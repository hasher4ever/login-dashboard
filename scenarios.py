"""
Mock event scenarios for the login-dashboard prototype.

Each scenario is a list of (delay_ms, event_dict) tuples. delay_ms is how long
to wait BEFORE emitting that event (relative to the previous one). The
replayer fills in `ts` at emit time so the live feed always looks fresh.

Event shape:
    {
        "success":        bool,
        "ip":             str,
        "username":       str,
        "user_agent":     str,
        "failure_reason": str | None,
    }
"""

# Real-looking-but-RFC5737-reserved IPs so nobody confuses these with real
# production data. 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 are TEST-NET.
OFFICE_IPS = [
    "198.51.100.12",
    "198.51.100.34",
    "198.51.100.78",
]
MOBILE_IPS = [
    "192.0.2.41",
    "192.0.2.99",
    "192.0.2.155",
]
ATTACKER_IP = "203.0.113.7"
TOKEN_THIEF_IP = "203.0.113.201"

DISPATCHERS = [
    "islom@tms360.io",
    "ravshan@tms360.io",
    "abrorxon@tms360.io",
    "sultonbek.nazarov.work@tms360.io",
    "abubakr@tms360.io",
    "dispatcher.kim@tms360.io",
]

CHROME = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36"
SAFARI = "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15"
FIREFOX = "Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/122.0"
CURL = "curl/8.4.0"
PYTHON = "python-requests/2.31.0"


def _ev(success, ip, username, user_agent=CHROME, failure_reason=None):
    return {
        "success": success,
        "ip": ip,
        "username": username,
        "user_agent": user_agent,
        "failure_reason": failure_reason,
    }


# --- steady_state: baseline traffic, ~1 event per 1.5s, 95% success ----------
def _steady_state():
    out = []
    pattern = [
        (1200, _ev(True, OFFICE_IPS[0], DISPATCHERS[0], CHROME)),
        (1700, _ev(True, OFFICE_IPS[1], DISPATCHERS[1], CHROME)),
        (1100, _ev(True, MOBILE_IPS[0], DISPATCHERS[2], SAFARI)),
        (1800, _ev(True, OFFICE_IPS[2], DISPATCHERS[3], CHROME)),
        (1400, _ev(False, OFFICE_IPS[0], DISPATCHERS[4], CHROME, "wrong_password")),
        (1300, _ev(True, MOBILE_IPS[1], DISPATCHERS[4], SAFARI)),
        (1600, _ev(True, OFFICE_IPS[1], DISPATCHERS[5], FIREFOX)),
        (1500, _ev(True, OFFICE_IPS[0], DISPATCHERS[0], CHROME)),
        (1200, _ev(True, MOBILE_IPS[2], DISPATCHERS[1], SAFARI)),
        (1700, _ev(True, OFFICE_IPS[2], DISPATCHERS[3], CHROME)),
        (1400, _ev(False, OFFICE_IPS[1], DISPATCHERS[2], CHROME, "expired_session")),
        (1300, _ev(True, MOBILE_IPS[0], DISPATCHERS[5], SAFARI)),
        (1600, _ev(True, OFFICE_IPS[0], DISPATCHERS[4], CHROME)),
        (1500, _ev(True, OFFICE_IPS[1], DISPATCHERS[0], CHROME)),
    ]
    # Repeat the pattern twice for ~45s of demo
    out.extend(pattern)
    out.extend(pattern)
    return out


# --- brute_force: one IP, ~40 attempts in 30s, rotating usernames, all fail --
def _brute_force():
    targets = [
        "admin", "root", "administrator", "support", "ceo@tms360.io",
        "info@tms360.io", "test@tms360.io", "demo@tms360.io",
        "abubakr", "abubakr@tms360.io", "manager", "ops@tms360.io",
        "billing@tms360.io", "noc@tms360.io", "security@tms360.io",
        "owner@tms360.io", "admin@tms360.io", "postmaster@tms360.io",
        "dev@tms360.io", "qa@tms360.io",
    ]
    out = []
    # 40 attempts total: walk the list twice, ~750ms cadence
    for i in range(40):
        username = targets[i % len(targets)]
        out.append((750, _ev(False, ATTACKER_IP, username, CURL, "invalid_credentials")))
    return out


# --- cred_stuffing: 12 IPs, same 3 usernames, 1 successful (alarming) --------
def _cred_stuffing():
    distributed_ips = [
        "192.0.2.11", "192.0.2.22", "192.0.2.33", "192.0.2.44",
        "203.0.113.21", "203.0.113.42", "203.0.113.63", "203.0.113.84",
        "198.51.100.51", "198.51.100.72", "198.51.100.93", "198.51.100.114",
    ]
    targets = ["islom@tms360.io", "ravshan@tms360.io", "abubakr@tms360.io"]
    uas = [CHROME, FIREFOX, PYTHON, CURL]
    out = []
    for i, ip in enumerate(distributed_ips):
        username = targets[i % len(targets)]
        ua = uas[i % len(uas)]
        # 11 of 12 fail; the 4th attempt succeeds (the demo-scary moment)
        success = (i == 3)
        reason = None if success else "invalid_credentials"
        out.append((2200, _ev(success, ip, username, ua, reason)))
    return out


# --- geo_anomaly: legit user logs in, then "same user" from far-away IP ------
def _geo_anomaly():
    # ts t=0: dispatcher logs in normally from office
    # ts t~3s: another login for SAME username from a wildly different IP
    return [
        (500, _ev(True, OFFICE_IPS[0], DISPATCHERS[0], CHROME)),
        (3000, _ev(True, OFFICE_IPS[1], DISPATCHERS[1], CHROME)),
        (1500, _ev(True, OFFICE_IPS[2], DISPATCHERS[2], CHROME)),
        # Token theft pattern: islom@ just logged in from office above,
        # now appears from TOKEN_THIEF_IP using curl (suspicious UA shift too).
        (4000, _ev(True, TOKEN_THIEF_IP, DISPATCHERS[0], CURL)),
        (2000, _ev(False, TOKEN_THIEF_IP, DISPATCHERS[0], CURL, "mfa_required")),
        (1500, _ev(True, OFFICE_IPS[0], DISPATCHERS[3], CHROME)),
    ]


SCENARIOS = {
    "steady_state": _steady_state(),
    "brute_force": _brute_force(),
    "cred_stuffing": _cred_stuffing(),
    "geo_anomaly": _geo_anomaly(),
}
