FROM python:3.12-slim
WORKDIR /app

# Build-time:
#   - curl + ca-certificates: geo-data download (DB-IP City Lite, CC-BY-4.0)
#   - gcc + libsnappy-dev + python3-dev: building the python-snappy C extension
#     which kafka-python loads on demand to decompress auth_events batches
# Runtime: libsnappy1v5 stays; build tools are removed to keep the image small.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       curl ca-certificates \
       libsnappy1v5 libsnappy-dev gcc python3-dev \
  && rm -rf /var/lib/apt/lists/*

# Install deps first so cache survives source edits.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove libsnappy-dev gcc python3-dev \
  && rm -rf /var/lib/apt/lists/*

COPY . .

# Pull a recent DB-IP City Lite MMDB so the Map tab can resolve real IPs.
# Falls back gracefully (geo.py returns "unknown location") if this fails.
RUN bash scripts/setup_dbip.sh || echo "[geo] mmdb download failed at build — map will use fallback"

ENV PYTHONUNBUFFERED=1
ENV PORT=8000
EXPOSE 8000

CMD ["python", "main.py"]
