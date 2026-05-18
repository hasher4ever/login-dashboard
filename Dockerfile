FROM python:3.12-slim
WORKDIR /app

# Tools needed by the geo-data download step (DB-IP City Lite, CC-BY-4.0).
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Install deps first so cache survives source edits.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pull a recent DB-IP City Lite MMDB so the Map tab can resolve real IPs.
# Falls back gracefully (geo.py returns "unknown location") if this fails.
RUN bash scripts/setup_dbip.sh || echo "[geo] mmdb download failed at build — map will use fallback"

ENV PYTHONUNBUFFERED=1
ENV PORT=8000
EXPOSE 8000

CMD ["python", "main.py"]
