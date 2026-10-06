# traefik-adguard-dns

Automatically synchronizes Traefik HTTP router hosts to AdGuard Home DNS rewrites.

## Docker image

Published to:

`ghcr.io/xstar97/traefik-adguard-dns`

## Configuration

### Environment variables

| Variable           | Required | Default                       | Description                                              |
| ------------------ | :------: | ----------------------------- | -------------------------------------------------------- |
| `ADGUARD_URL`      |    Yes   | —                             | AdGuard Home URL                                         |
| `ADGUARD_USERNAME` |    Yes   | —                             | AdGuard Home username                                    |
| `ADGUARD_PASSWORD` |    Yes   | —                             | AdGuard Home password                                    |
| `TRAEFIK_API_URL`  |    No    | `http://traefik:8080`         | Traefik API URL                                          |
| `POLL_INTERVAL`    |    No    | `30`                          | Reconciliation interval in seconds                       |
| `STATE_FILE`       |    No    | `/data/managed-rewrites.json` | File used to track DNS rewrites managed by the companion |
| `LOG_LEVEL`        |    No    | `INFO`                        | Logging level                                            |

## Docker

```bash
docker run -d \
  --name traefik-adguard-dns \
  -e ADGUARD_URL=http://adguard:3000 \
  -e ADGUARD_USERNAME=admin \
  -e ADGUARD_PASSWORD=secret \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v adguard-dns-data:/data \
  ghcr.io/xstar97/traefik-adguard-dns:latest
```

The container requires access to the Docker socket to discover Traefik router labels.

## Docker labels

Containers opt in by adding the `adguard.dns` label:

```yaml
labels:
  adguard.dns: 10.0.0.XXX # traefik.local
```

The value can be an IP address or hostname.

For example:

```yaml
services:
  dozzle:
    image: amir20/dozzle:latest
    labels:
      adguard.dns: 10.0.0.XXX # traefik.local
      traefik.http.routers.dozzle.rule: Host(`dozzle.local`)
```

The companion uses the Traefik API as the source of truth for router hosts and the `adguard.dns` label to determine the DNS rewrite target.

## Managed records

The companion maintains an ownership state file at:

```text
/data/managed-rewrites.json
```

Only DNS rewrites created by this container are eligible for automatic removal.

Existing AdGuard Home rewrites that were not created by the companion are preserved and never deleted.

When a Traefik router is removed or its `adguard.dns` target is no longer present, the corresponding managed rewrite is automatically removed.

## Healthcheck

The container supports:

```bash
docker exec traefik-adguard-dns \
  python /app/main.py --healthcheck
```

The healthcheck verifies connectivity to both the Traefik API and AdGuard Home.
