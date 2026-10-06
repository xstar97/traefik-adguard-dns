FROM python:3.12-alpine

LABEL org.opencontainers.image.title="traefik-adguard-dns" \
      org.opencontainers.image.description="Sync Traefik router hosts to AdGuard Home DNS rewrites" \
      org.opencontainers.image.source="https://github.com/xstar97/traefik-adguard-dns"

ENV PYTHONUNBUFFERED=1 \
    STATE_FILE=/data/managed-rewrites.json

WORKDIR /app
COPY adguard_dns.py /app/adguard_dns.py

RUN mkdir -p /data
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
  CMD ["python", "/app/adguard_dns.py", "--healthcheck"]

ENTRYPOINT ["python", "/app/adguard_dns.py"]
