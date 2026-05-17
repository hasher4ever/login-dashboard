#!/usr/bin/env bash
# Download MaxMind GeoLite2-City.mmdb into data/.
#
# Prerequisites:
#   1. Sign up free at https://www.maxmind.com/en/geolite2/signup
#   2. Generate a license key in your account portal
#   3. Export it:  export MAXMIND_LICENSE_KEY=xxxxxxxxxxxxx
#   4. Run this script: ./scripts/setup_geolite2.sh
#
# The DB is refreshed by MaxMind ~twice a week. Re-run to update.

set -euo pipefail

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "error: MAXMIND_LICENSE_KEY not set." >&2
  echo "  1. Sign up: https://www.maxmind.com/en/geolite2/signup" >&2
  echo "  2. Generate a license key in your account portal" >&2
  echo "  3. export MAXMIND_LICENSE_KEY=xxxxxxxxxxxxx" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
TARBALL="data/GeoLite2-City.tar.gz"

echo "[geo] downloading GeoLite2-City..."
curl --fail --silent --show-error --location -o "$TARBALL" "$URL"

echo "[geo] extracting..."
tar -xzf "$TARBALL" -C data/ --strip-components=1 --wildcards '*/GeoLite2-City.mmdb'

rm -f "$TARBALL"

if [[ -f data/GeoLite2-City.mmdb ]]; then
  SIZE=$(du -h data/GeoLite2-City.mmdb | cut -f1)
  echo "[geo] OK — data/GeoLite2-City.mmdb (${SIZE})"
else
  echo "error: GeoLite2-City.mmdb not found after extract" >&2
  exit 1
fi
