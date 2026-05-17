"""GeoIP lookup backed by MaxMind GeoLite2-City (offline MMDB).

Resolution order for `geolocate(ip)`:

1. `IP_GEO` demo override — the RFC5737 mock IPs used by `scenarios.py` don't
   exist in any real GeoIP DB, so we keep a hand-typed table for them.
2. In-memory cache — every successful lookup is memoized for the life of
   the process. Lookups against MMDB are ~10us but we still want zero
   allocations on the hot render path.
3. Private / loopback / reserved IPs — returned as ("private/reserved")
   without hitting the DB.
4. MaxMind GeoLite2-City MMDB at `data/GeoLite2-City.mmdb`.
5. Fallback to mid-Atlantic ("unknown location") if anything above fails or
   the DB is missing.

Setup the MMDB once with `scripts/setup_geolite2.sh` (uses
`MAXMIND_LICENSE_KEY` env var; free signup at https://www.maxmind.com/).
"""

import ipaddress
import os
import threading
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
# Tries MaxMind GeoLite2 first (needs license key), falls back to DB-IP City
# Lite (no signup, direct download). Same MMDB format — `maxminddb` reads
# both. See scripts/setup_geolite2.sh and scripts/setup_dbip.sh.
_MMDB_CANDIDATES = [
    os.path.join(_DATA_DIR, "GeoLite2-City.mmdb"),
    os.path.join(_DATA_DIR, "dbip-city-lite.mmdb"),
]
MMDB_PATH = next((p for p in _MMDB_CANDIDATES if os.path.exists(p)), _MMDB_CANDIDATES[0])
FALLBACK_LATLNG = (0.0, -30.0)
FALLBACK_LABEL = "unknown location"

# Mock IPs from scenarios.py — RFC5737 reserved ranges that don't appear in
# any real GeoIP database. Keep hand-typed coords so the demo story (Tashkent
# office, Moscow attacker, Lagos token-thief, etc.) still renders on the map.
IP_GEO: dict[str, tuple[float, float, str]] = {
    "198.51.100.12":  (41.311, 69.279, "Tashkent, UZ"),
    "198.51.100.34":  (41.305, 69.291, "Tashkent, UZ"),
    "198.51.100.78":  (41.299, 69.272, "Tashkent, UZ"),
    "192.0.2.41":     (39.654, 66.975, "Samarkand, UZ"),
    "192.0.2.99":     (40.785, 72.336, "Andijan, UZ"),
    "192.0.2.155":    (41.553, 60.633, "Urgench, UZ"),
    "203.0.113.7":    (55.751, 37.618, "Moscow, RU"),
    "203.0.113.201":  (6.524,  3.379,  "Lagos, NG"),
    "192.0.2.11":     (52.520, 13.405, "Berlin, DE"),
    "192.0.2.22":     (-23.55, -46.633,"São Paulo, BR"),
    "192.0.2.33":     (28.613, 77.209, "New Delhi, IN"),
    "192.0.2.44":     (40.712, -74.006,"New York, US"),
    "203.0.113.21":   (35.689, 139.692,"Tokyo, JP"),
    "203.0.113.42":   (-33.868,151.209,"Sydney, AU"),
    "203.0.113.63":   (51.507, -0.128, "London, GB"),
    "203.0.113.84":   (19.432, -99.133,"Mexico City, MX"),
    "198.51.100.51":  (37.774, -122.419,"San Francisco, US"),
    "198.51.100.72":  (1.352,  103.820,"Singapore, SG"),
    "198.51.100.93":  (59.329, 18.069, "Stockholm, SE"),
    "198.51.100.114": (-1.286, 36.817, "Nairobi, KE"),
}

_cache: dict[str, tuple[float, float, str]] = {}
_cache_lock = threading.Lock()
_reader = None
_reader_warned = False


def _open_reader():
    global _reader, _reader_warned
    if _reader is not None:
        return _reader
    if not os.path.exists(MMDB_PATH):
        if not _reader_warned:
            print(
                f"[geo] MMDB not found at {MMDB_PATH} — real IPs will fall back to "
                f"'unknown'. Run scripts/setup_geolite2.sh to download it.",
                flush=True,
            )
            _reader_warned = True
        return None
    try:
        import maxminddb
        _reader = maxminddb.open_database(MMDB_PATH)
        return _reader
    except ImportError:
        if not _reader_warned:
            print(
                "[geo] maxminddb library not installed — install with "
                "`pip install -r requirements.txt`. Falling back to 'unknown'.",
                flush=True,
            )
            _reader_warned = True
        return None
    except (OSError, ValueError) as e:
        if not _reader_warned:
            print(f"[geo] failed to open {MMDB_PATH}: {e}", flush=True)
            _reader_warned = True
        return None


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


def _lookup_mmdb(ip: str) -> Optional[tuple[float, float, str]]:
    reader = _open_reader()
    if reader is None:
        return None
    try:
        record = reader.get(ip)
    except ValueError:
        return None
    if not record:
        return None
    loc = record.get("location") or {}
    lat = loc.get("latitude")
    lng = loc.get("longitude")
    if lat is None or lng is None:
        return None
    city = ((record.get("city") or {}).get("names") or {}).get("en", "")
    cc = (record.get("country") or {}).get("iso_code", "")
    if city and cc:
        label = f"{city}, {cc}"
    elif cc:
        label = cc
    else:
        label = ((record.get("country") or {}).get("names") or {}).get("en") or FALLBACK_LABEL
    return (float(lat), float(lng), label)


def geolocate(ip: str) -> tuple[float, float, str]:
    """Return (lat, lng, label) for an IP."""
    if ip in IP_GEO:
        return IP_GEO[ip]
    with _cache_lock:
        if ip in _cache:
            return _cache[ip]
    if _is_private(ip):
        result = (0.0, 0.0, "private/reserved")
    else:
        result = _lookup_mmdb(ip) or (FALLBACK_LATLNG[0], FALLBACK_LATLNG[1], FALLBACK_LABEL)
    with _cache_lock:
        _cache[ip] = result
    return result
