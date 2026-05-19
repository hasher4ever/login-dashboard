#!/usr/bin/env bash
# Download the free IP2Location LITE DB11 BIN (country, region, city, ZIP,
# lat/lon, tz) into data/. Published monthly under CC-BY-SA 4.0.
#
# Prerequisites:
#   1. Sign up free at https://lite.ip2location.com/
#   2. Copy your download token from the LITE dashboard
#   3. Export it:  export IP2LOCATION_TOKEN=xxxxxxxxxxxxx
#   4. Run this script: ./scripts/setup_ip2location.sh
#
# Re-run any time to refresh. IP2Location publishes new DB11 BINs on the
# 1st of every month — geo_refresh.py schedules around that cadence.

set -euo pipefail

if [[ -z "${IP2LOCATION_TOKEN:-}" ]]; then
  echo "error: IP2LOCATION_TOKEN not set." >&2
  echo "  1. Sign up: https://lite.ip2location.com/" >&2
  echo "  2. Copy your LITE token from the dashboard" >&2
  echo "  3. export IP2LOCATION_TOKEN=xxxxxxxxxxxxx" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

URL="https://www.ip2location.com/download/?token=${IP2LOCATION_TOKEN}&file=DB11LITEBIN"
ZIP="data/IP2LOCATION-LITE-DB11.zip"
TARGET="data/IP2LOCATION-LITE-DB11.BIN"

mkdir -p data

echo "[geo] downloading IP2Location LITE DB11..."
curl --fail --silent --show-error --location -o "$ZIP" "$URL"

# Their CDN serves the file straight when the token is valid. When it
# isn't, the response is an HTML error page — sniff for the ZIP magic
# before unzipping so we don't silently leave a stale BIN in place.
if ! unzip -l "$ZIP" >/dev/null 2>&1; then
  echo "error: download isn't a ZIP — token may be wrong or rate-limited" >&2
  head -c 200 "$ZIP" >&2 || true
  rm -f "$ZIP"
  exit 1
fi

echo "[geo] extracting..."
unzip -p "$ZIP" "IP2LOCATION-LITE-DB11.BIN" > "$TARGET"
rm -f "$ZIP"

if [[ -s "$TARGET" ]]; then
  SIZE=$(du -h "$TARGET" | cut -f1)
  echo "[geo] OK — ${TARGET} (${SIZE})"
else
  echo "error: extracted BIN is empty" >&2
  rm -f "$TARGET"
  exit 1
fi
