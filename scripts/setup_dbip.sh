#!/usr/bin/env bash
# Download the free DB-IP City Lite MMDB into data/. No signup, no API key.
#
# Use this if you don't have a MaxMind license key yet. The DB is published
# monthly at https://db-ip.com/db/lite.php under a CC-BY-4.0 license.
# Re-run on the 1st of any month to refresh.

set -euo pipefail

cd "$(dirname "$0")/.."

# Try the current month, fall back through the last few months in case the
# current one hasn't been published yet.
TODAY_YM=$(date -u +%Y-%m)
LAST_YM=$(date -u -v-1m +%Y-%m 2>/dev/null || date -u --date='1 month ago' +%Y-%m)
PREV_YM=$(date -u -v-2m +%Y-%m 2>/dev/null || date -u --date='2 months ago' +%Y-%m)

ARCHIVE="data/dbip-city-lite.mmdb.gz"
TARGET="data/dbip-city-lite.mmdb"

for YM in "$TODAY_YM" "$LAST_YM" "$PREV_YM"; do
  URL="https://download.db-ip.com/free/dbip-city-lite-${YM}.mmdb.gz"
  echo "[geo] trying ${YM}..."
  if curl --fail --silent --show-error --location -o "$ARCHIVE" "$URL"; then
    echo "[geo] downloaded ${YM}"
    gunzip -f "$ARCHIVE"
    # The extracted file is dbip-city-lite-YYYY-MM.mmdb — rename to a
    # version-less filename so geo.py finds it without an env var.
    mv "data/dbip-city-lite-${YM}.mmdb" "$TARGET" 2>/dev/null \
      || mv "data/dbip-city-lite.mmdb" "$TARGET" 2>/dev/null \
      || true
    if [[ -f "$TARGET" ]]; then
      SIZE=$(du -h "$TARGET" | cut -f1)
      echo "[geo] OK — ${TARGET} (${SIZE})"
      exit 0
    fi
  fi
done

echo "error: could not download dbip-city-lite for any recent month" >&2
exit 1
