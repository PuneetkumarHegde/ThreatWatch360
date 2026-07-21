# AlertIQ 2.0 - Backend Dockerfile
#
# IMPORTANT: live packet capture needs raw-socket access, which Docker's
# default network isolation blocks. To capture real traffic from inside
# this container you must run it with:
#   --network host --cap-add=NET_RAW --cap-add=NET_ADMIN
# (Linux only - Docker Desktop on Windows/macOS cannot bridge host
# network interfaces this way; run the backend natively there instead,
# or use this container purely for the API/ML/Demo-Mode functionality.)

FROM python:3.12-slim

# libpcap for Scapy's raw capture backend, gcc for any packages that
# need to compile a native extension (lightgbm/xgboost/catboost wheels
# are prebuilt for linux/amd64 so this is mostly a safety net).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    iptables \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-trained models ship in the image (ai_engine/models_store/) so the
# container is usable immediately without a training step. Retrain by
# execing in: `docker exec -it <container> python3 -m ai_engine.train`
ENV ALERTIQ_DB_PATH=/app/data/alertiq.db
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
