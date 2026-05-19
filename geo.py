"""Pluggable IP geolocation with operator-selectable backends.

Backends are free, DB-only (no runtime API call). Each one is downloaded
once and refreshed in-process by `geo_refresh.py` on the cadence the
upstream publishes at:

  - geolite2      MaxMind GeoLite2-City (MMDB, ~2x/week)         needs MAXMIND_LICENSE_KEY
  - dbip          DB-IP City Lite       (MMDB, monthly)          no auth
  - ip2location   IP2Location LITE DB11 (BIN,  monthly)          needs IP2LOCATION_TOKEN
  - ensemble      majority vote over whichever of the above are loaded

Front-end picks the backend per request via ?geo=<name>. If the chosen
backend isn't loaded the call transparently falls back to whatever IS
loaded, in this preference order:

    ensemble > ip2location > dbip > geolite2

The four canned scenario IPs (`IP_GEO`) and private/reserved IPs short-
circuit every backend — they're not real public ranges and would either
be missed or mislabelled.
"""

from __future__ import annotations

import ipaddress
import os
import threading
from collections import Counter
from typing import Optional

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# ----- file paths (kept module-level so geo_refresh.py can stat them) ------

GEOLITE2_PATH    = os.path.join(_DATA_DIR, "GeoLite2-City.mmdb")
DBIP_PATH        = os.path.join(_DATA_DIR, "dbip-city-lite.mmdb")
IP2LOCATION_PATH = os.path.join(_DATA_DIR, "IP2LOCATION-LITE-DB11.BIN")

DEFAULT_BACKEND = os.environ.get("GEO_DEFAULT_BACKEND", "ensemble")

FALLBACK_LATLNG = (0.0, -30.0)
FALLBACK_LABEL = "unknown location"

# Hand-typed coords for the canned scenarios.py demo IPs (RFC5737 / TEST-NET
# ranges — they don't appear in any real GeoIP DB).
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

# ----- per-backend reader management ---------------------------------------

class _Backend:
    """Lazy-opened single-DB lookup. Reader is reopened on refresh()."""

    name: str
    path: str
    label: str
    update_cadence: str  # human-readable, surfaced via /api/geo-backends

    def __init__(self):
        self._reader = None
        self._lock = threading.Lock()
        self._warned = False
        self._last_loaded: Optional[float] = None

    def is_available(self) -> bool:
        return os.path.exists(self.path)

    def refresh(self) -> None:
        """Drop the open reader so the next lookup reopens the on-disk file.
        Called by geo_refresh.py after a successful download."""
        with self._lock:
            r = self._reader
            self._reader = None
            self._warned = False
        try:
            if r is not None and hasattr(r, "close"):
                r.close()
        except Exception:
            pass

    def _open(self):
        raise NotImplementedError

    def _query(self, reader, ip: str) -> Optional[tuple[float, float, str]]:
        raise NotImplementedError

    def _get_reader(self):
        if self._reader is not None:
            return self._reader
        if not os.path.exists(self.path):
            if not self._warned:
                print(f"[geo] {self.name}: db not at {self.path}", flush=True)
                self._warned = True
            return None
        with self._lock:
            if self._reader is not None:
                return self._reader
            try:
                self._reader = self._open()
                self._warned = False
                return self._reader
            except ImportError as e:
                if not self._warned:
                    print(f"[geo] {self.name}: missing library — {e}", flush=True)
                    self._warned = True
            except Exception as e:
                if not self._warned:
                    print(f"[geo] {self.name}: open failed — {e}", flush=True)
                    self._warned = True
            return None

    def lookup(self, ip: str) -> Optional[tuple[float, float, str]]:
        reader = self._get_reader()
        if reader is None:
            return None
        try:
            return self._query(reader, ip)
        except Exception:
            return None


class _MMDB(_Backend):
    """Shared base for the two MMDB-format backends (MaxMind, DB-IP)."""

    def _open(self):
        import maxminddb
        return maxminddb.open_database(self.path)

    def _query(self, reader, ip: str) -> Optional[tuple[float, float, str]]:
        record = reader.get(ip)
        if not record:
            return None
        loc = record.get("location") or {}
        lat = loc.get("latitude")
        lng = loc.get("longitude")
        if lat is None or lng is None:
            return None
        city = ((record.get("city") or {}).get("names") or {}).get("en", "")
        subs = record.get("subdivisions") or []
        region = ""
        if subs:
            region = (subs[0].get("names") or {}).get("en", "") or subs[0].get("iso_code", "")
        cc = (record.get("country") or {}).get("iso_code", "")
        return (float(lat), float(lng), _label(city, region, cc))


class GeoLite2(_MMDB):
    name = "geolite2"
    path = GEOLITE2_PATH
    label = "MaxMind GeoLite2-City"
    update_cadence = "twice weekly (Tue / Fri)"


class DBIP(_MMDB):
    name = "dbip"
    path = DBIP_PATH
    label = "DB-IP City Lite"
    update_cadence = "monthly (1st)"


class IP2Location(_Backend):
    name = "ip2location"
    path = IP2LOCATION_PATH
    label = "IP2Location LITE DB11"
    update_cadence = "monthly (1st)"

    def _open(self):
        import IP2Location  # pip install IP2Location
        return IP2Location.IP2Location(self.path)

    def _query(self, reader, ip: str) -> Optional[tuple[float, float, str]]:
        rec = reader.get_all(ip)
        if rec is None:
            return None
        lat = getattr(rec, "latitude", None)
        lng = getattr(rec, "longitude", None)
        if lat is None or lng is None:
            return None
        city = getattr(rec, "city", "") or ""
        region = getattr(rec, "region", "") or ""
        cc = getattr(rec, "country_short", "") or ""
        # IP2Location uses "-" as the sentinel for "unknown" in LITE rows
        city = "" if city in ("-", "None") else city
        region = "" if region in ("-", "None") else region
        cc = "" if cc in ("-", "None") else cc
        return (float(lat), float(lng), _label(city, region, cc))


# Order is the precedence used when ?geo= asks for a backend that isn't
# loaded — first available wins. Also the order shown in /api/geo-backends.
_BACKENDS: list[_Backend] = [GeoLite2(), DBIP(), IP2Location()]
_BY_NAME: dict[str, _Backend] = {b.name: b for b in _BACKENDS}


# ----- ensemble: majority vote on (city, country) --------------------------

def _ensemble_lookup(ip: str) -> Optional[tuple[float, float, str]]:
    """Run every loaded backend; return the entry that the most backends
    agree on by (city, country) pair. Tiebreak by IP2Location > DB-IP >
    GeoLite2 (their relative city-coverage ranking from the APNIC study)."""
    candidates = []  # (backend_name, (lat, lng, label))
    for b in _BACKENDS:
        out = b.lookup(ip)
        if out is not None:
            candidates.append((b.name, out))
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0][1]

    # Key by (city, country) so different lat/lon precisions don't fracture.
    def key(label: str) -> str:
        return label.lower().strip()

    counter = Counter(key(c[1][2]) for c in candidates)
    top_key, top_count = counter.most_common(1)[0]

    if top_count >= 2:
        # Among backends that agree, prefer the highest-precedence one.
        prec = {"ip2location": 0, "dbip": 1, "geolite2": 2}
        agreeing = [c for c in candidates if key(c[1][2]) == top_key]
        agreeing.sort(key=lambda c: prec.get(c[0], 9))
        return agreeing[0][1]

    # Total disagreement — pick by tiebreak precedence among returned ones.
    prec = {"ip2location": 0, "dbip": 1, "geolite2": 2}
    candidates.sort(key=lambda c: prec.get(c[0], 9))
    return candidates[0][1]


# ----- helpers -------------------------------------------------------------

def is_low_confidence_label(label: str) -> bool:
    """True if the label is country-only or a pure fallback.

    Country-only labels (e.g. "US", "GB") mean the backing GeoIP DB
    knew the country but couldn't pinpoint a city — so the (lat, lng)
    is the DB's country-centroid sentinel (Cheney Reservoir for US,
    Brunswick for DE, etc.). Markers placed on those coords are
    geographically meaningless and worth flagging visually so the
    operator doesn't read them as real Kansas / Brunswick traffic."""
    if not label or label == FALLBACK_LABEL or label == "private/reserved":
        return True
    parts = [p.strip() for p in label.split(",") if p.strip()]
    return len(parts) <= 1


def _label(city: str, region: str, cc: str) -> str:
    """Render a human-readable place string. Region only shown when it
    isn't duplicating the city (e.g. "New York, NY, US" but "Tashkent, UZ")
    and is suppressed entirely when missing."""
    bits = []
    if city:
        bits.append(city)
    if region and region != city:
        bits.append(region)
    if cc:
        bits.append(cc)
    return ", ".join(bits) if bits else FALLBACK_LABEL


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


# ----- per-(ip, backend) memoization ---------------------------------------
#
# Cache key is (ip, backend_choice) so switching the FE selector doesn't
# return the previously-cached answer from a different DB. Cleared
# wholesale when a backend refresh succeeds (geo_refresh.py calls
# `invalidate_cache()`).

_cache: dict[tuple[str, str], tuple[float, float, str]] = {}
_cache_lock = threading.Lock()


def invalidate_cache(backend: Optional[str] = None) -> None:
    """Drop cached lookups. If a backend name is given, only entries that
    were resolved by that backend (or by `ensemble`, which depends on it)
    are evicted."""
    with _cache_lock:
        if backend is None:
            _cache.clear()
            return
        # Ensemble depends on every backend, so its rows die whenever
        # any single backend refreshes.
        to_drop = [k for k in _cache if k[1] in (backend, "ensemble")]
        for k in to_drop:
            del _cache[k]


# ----- public API ----------------------------------------------------------

def available_backends() -> list[dict]:
    """Snapshot of every backend's load state. Surfaced via /api/geo-backends
    so the FE selector can disable unloaded options and show staleness."""
    out = []
    for b in _BACKENDS:
        mtime = None
        if os.path.exists(b.path):
            try:
                mtime = os.path.getmtime(b.path)
            except OSError:
                mtime = None
        out.append({
            "name": b.name,
            "label": b.label,
            "available": b.is_available(),
            "path": os.path.basename(b.path),
            "mtime": mtime,
            "update_cadence": b.update_cadence,
        })
    # Ensemble is available whenever ≥1 backend is.
    out.append({
        "name": "ensemble",
        "label": "Ensemble (majority vote)",
        "available": any(b.is_available() for b in _BACKENDS),
        "path": None,
        "mtime": None,
        "update_cadence": "follows constituent DBs",
    })
    return out


def _resolve_backend(choice: Optional[str]) -> str:
    """Map a (possibly invalid or unloaded) choice onto an actually-usable
    backend name. Order of preference matches what the selector shows."""
    candidates: list[str]
    if choice == "ensemble" or choice is None or choice == "":
        candidates = ["ensemble", "ip2location", "dbip", "geolite2"]
        if choice and choice != "ensemble":
            candidates = [choice] + [c for c in candidates if c != choice]
    elif choice in _BY_NAME:
        candidates = [choice, "ip2location", "dbip", "geolite2"]
    else:
        candidates = ["ensemble", "ip2location", "dbip", "geolite2"]

    for c in candidates:
        if c == "ensemble" and any(b.is_available() for b in _BACKENDS):
            return "ensemble"
        if c in _BY_NAME and _BY_NAME[c].is_available():
            return c
    return "none"


def geolocate(
    ip: str,
    backend: Optional[str] = None,
) -> tuple[float, float, str]:
    """Return (lat, lng, label) for an IP using the chosen backend.

    `backend` is None, "ensemble", or one of the keys in `_BY_NAME`. An
    unknown / unloaded choice silently falls back to whatever IS loaded
    (preference: ensemble > ip2location > dbip > geolite2). The picked
    backend is encoded in the cache key so the next selector-switch
    re-runs the lookup against the newly-chosen DB."""
    if backend is None or backend == "":
        backend = DEFAULT_BACKEND
    if ip in IP_GEO:
        return IP_GEO[ip]

    resolved = _resolve_backend(backend)
    cache_key = (ip, resolved)
    with _cache_lock:
        hit = _cache.get(cache_key)
        if hit is not None:
            return hit

    if _is_private(ip):
        result = (0.0, 0.0, "private/reserved")
    elif resolved == "ensemble":
        result = _ensemble_lookup(ip) or (FALLBACK_LATLNG[0], FALLBACK_LATLNG[1], FALLBACK_LABEL)
    elif resolved in _BY_NAME:
        result = _BY_NAME[resolved].lookup(ip) or (FALLBACK_LATLNG[0], FALLBACK_LATLNG[1], FALLBACK_LABEL)
    else:
        result = (FALLBACK_LATLNG[0], FALLBACK_LATLNG[1], FALLBACK_LABEL)

    with _cache_lock:
        _cache[cache_key] = result
    return result


# Back-compat shim — call sites that pass no backend still work.
def geolocate_default(ip: str) -> tuple[float, float, str]:
    return geolocate(ip)
