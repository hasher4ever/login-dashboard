FROM python:3.12-slim
WORKDIR /app

# Build-time:
#   - curl + ca-certificates: geo-data download (DB-IP, GeoLite2, IP2Location)
#   - unzip: IP2Location LITE BIN ships in a zip archive
#   - gcc + libsnappy-dev + python3-dev: building the python-snappy C extension
#     which kafka-python loads on demand to decompress auth_events batches
# Runtime: libsnappy1v5 + unzip stay; build tools are removed to keep the
# image small. unzip is kept because geo_refresh.py re-runs setup_ip2location.sh
# in-process on its monthly cadence.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       curl ca-certificates unzip \
       libsnappy1v5 libsnappy-dev gcc python3-dev \
  && rm -rf /var/lib/apt/lists/*

# Install deps first so cache survives source edits.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove libsnappy-dev gcc python3-dev \
  && rm -rf /var/lib/apt/lists/*

COPY . .

# Pull a recent DB-IP City Lite MMDB so the Map tab can resolve real IPs
# from first boot. GeoLite2 and IP2Location require auth tokens, so they're
# fetched at runtime by geo_refresh.py once the corresponding env var is
# set (MAXMIND_LICENSE_KEY, IP2LOCATION_TOKEN). All three are re-checked
# in-process on their upstream cadence — see geo_refresh.py.
RUN bash scripts/setup_dbip.sh || echo "[geo] dbip download failed at build — map will use fallback until first refresh"

ENV PYTHONUNBUFFERED=1
ENV PORT=8000
EXPOSE 8000

CMD ["python", "main.py"]
