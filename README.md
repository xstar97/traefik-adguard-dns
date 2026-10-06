# traefik-adguard-dns
## Docker image

Published to `ghcr.io/xstar97/traefik-adguard-dns`.

Required env: `ADGUARD_URL`, `ADGUARD_USERNAME`, `ADGUARD_PASSWORD`.
Optional: `TRAEFIK_API_URL` (default `http://traefik:8080`), `POLL_INTERVAL` (30), `STATE_FILE` (`/data/managed-rewrites.json`), `LOG_LEVEL`.

```bash
docker run -d --name traefik-adguard-dns \
  -e ADGUARD_URL=http://adguard:3000 -e ADGUARD_USERNAME=admin -e ADGUARD_PASSWORD=secret \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -v adguard-dns-data:/data \
  ghcr.io/xstar97/traefik-adguard-dns:latest
```

Containers opt in with the label `adguard.dns=<target ip or host>`.
