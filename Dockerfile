FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OT_BIND_HOST=0.0.0.0 \
    OT_LOG_PATH=/data/events.jsonl

RUN useradd --create-home --uid 10001 sensor
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY profiles ./profiles
RUN python -m pip install --no-cache-dir --upgrade "pip==26.2.1" && \
    python -m pip install --no-cache-dir --no-deps .

RUN mkdir /data && chown sensor:sensor /data
USER 10001:10001

EXPOSE 1502/tcp 1102/tcp 2404/tcp
VOLUME ["/data"]

ENTRYPOINT ["python", "-m", "ot_sentinel.sensor"]
