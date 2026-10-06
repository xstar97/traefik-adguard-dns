#!/usr/bin/env python3
"""Synchronize Traefik HTTP router hosts to AdGuard Home DNS rewrites."""

from __future__ import annotations

import base64
import http.client
import json
import logging
import os
import re
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
LOG = logging.getLogger("adguard-dns-companion")
STOP = False


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _clean(value: object) -> str:
    return str(value).strip().lower().rstrip(".")


# Configuration is loaded lazily so the module can be imported without env vars.
ADGUARD_URL = os.getenv("ADGUARD_URL", "").strip().rstrip("/")
ADGUARD_USERNAME = os.getenv("ADGUARD_USERNAME", "").strip()
ADGUARD_PASSWORD = os.getenv("ADGUARD_PASSWORD", "").strip()

TRAEFIK_API_URL = os.getenv("TRAEFIK_API_URL", "http://traefik:8080").rstrip("/")
if not TRAEFIK_API_URL.endswith("/api/http/routers"):
    TRAEFIK_API_URL = f"{TRAEFIK_API_URL}/api/http/routers"

DOCKER_SOCKET = "/var/run/docker.sock"
STATE_FILE = Path(os.getenv("STATE_FILE", "/data/managed-rewrites.json"))
POLL_INTERVAL = max(5, int(os.getenv("POLL_INTERVAL", "30")))

AUTH_TOKEN = base64.b64encode(
    f"{ADGUARD_USERNAME}:{ADGUARD_PASSWORD}".encode("utf-8")
).decode("ascii")

HOST_CALL = re.compile(r"(?<![A-Za-z])Host\(([^)]*)\)", re.IGNORECASE)
QUOTED_HOST = re.compile(r"""[`'"]([^`'"]+)[`'"]""")
DOCKER_ROUTER_LABEL = re.compile(r"^traefik\.http\.routers\.([^\.]+)\.rule$")


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> object:
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    data = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(
        url, data=data, headers=request_headers, method=method
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"request to {url} failed ({error.code}): {detail}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"request to {url} failed: {error}") from error

    if not payload:
        return None

    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"request to {url} returned invalid JSON: {payload[:500]!r}"
        ) from error


class DockerHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects through the Docker Unix socket."""

    def __init__(self, socket_path: str, timeout: float = 10):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def docker_request(
    path: str,
    method: str = "GET",
    data: dict | None = None,
    timeout: float = 10,
) -> object:
    body = None
    headers = {"Host": "localhost", "Accept": "application/json"}

    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    connection = DockerHTTPConnection(DOCKER_SOCKET, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()

        if response.status < 200 or response.status >= 300:
            raise RuntimeError(
                "Docker API returned HTTP "
                f"{response.status}: {payload.decode('utf-8', errors='replace')}"
            )

        if not payload:
            return None

        return json.loads(payload.decode("utf-8"))
    finally:
        connection.close()


def traefik_routers() -> list[dict]:
    result = request_json(TRAEFIK_API_URL)
    if not isinstance(result, list):
        raise RuntimeError("Traefik returned an unexpected router response")
    return [router for router in result if isinstance(router, dict)]


def docker_containers() -> list[dict]:
    result = docker_request("/containers/json?all=1")
    if not isinstance(result, list):
        raise RuntimeError("Docker returned an unexpected container response")
    return [container for container in result if isinstance(container, dict)]


def container_name(container: dict) -> str:
    names = container.get("Names") or []
    if not names:
        return ""
    return str(names[0]).lstrip("/")


def container_labels(container: dict) -> dict[str, str]:
    labels = container.get("Labels")
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items()}


def adguard_target(container: dict) -> str | None:
    target = container_labels(container).get("adguard.dns", "").strip()
    return target or None


def docker_router_targets(containers: list[dict]) -> dict[str, str]:
    """Build: Docker router name -> adguard.dns target."""
    result: dict[str, str] = {}

    for container in containers:
        labels = container_labels(container)
        target = labels.get("adguard.dns", "").strip()
        if not target:
            continue

        for label, value in labels.items():
            match = DOCKER_ROUTER_LABEL.match(label)
            if not match or not value:
                continue

            router_name = match.group(1)
            existing = result.get(router_name)

            if existing and existing != target:
                LOG.warning(
                    "Docker router %s has conflicting adguard.dns targets: "
                    "%s vs %s",
                    router_name,
                    existing,
                    target,
                )
                continue

            result[router_name] = target

    return result


def traefik_container_target(containers: list[dict]) -> str | None:
    """File-provider routers use the adguard.dns label on Traefik itself."""
    for container in containers:
        if container_name(container) != "traefik":
            continue
        target = adguard_target(container)
        if target:
            return target
    return None


def extract_hosts(rule: str) -> set[str]:
    """Extract exact Host() values. HostRegexp() is ignored."""
    hosts: set[str] = set()
    for call in HOST_CALL.findall(rule):
        for raw_host in QUOTED_HOST.findall(call):
            host = _clean(raw_host)
            if host:
                hosts.add(host)
    return hosts


def desired_records(
    routers: list[dict],
    containers: list[dict],
) -> set[tuple[str, str]]:
    """Build the desired exact (hostname, target) records."""
    docker_targets = docker_router_targets(containers)
    file_target = traefik_container_target(containers)
    desired: set[tuple[str, str]] = set()

    for router in routers:
        if router.get("status") == "disabled":
            continue

        hosts = extract_hosts(str(router.get("rule", "")))
        if not hosts:
            continue

        provider = str(router.get("provider", ""))
        router_name = str(router.get("name", ""))
        target: str | None = None

        if provider == "docker":
            lookup_name = router_name
            if "@" in lookup_name:
                lookup_name = lookup_name.rsplit("@", 1)[0]

            target = docker_targets.get(lookup_name)
            if not target:
                LOG.warning(
                    "No adguard.dns target found for Docker router %s; skipping",
                    router_name,
                )
                continue

        elif provider == "file":
            target = file_target
            if not target:
                LOG.warning(
                    "No adguard.dns target found on Traefik container; "
                    "skipping file router %s",
                    router_name,
                )
                continue

        else:
            LOG.debug(
                "Ignoring unsupported Traefik provider %s for router %s",
                provider,
                router_name,
            )
            continue

        for host in hosts:
            desired.add((host, target))

    return desired


def adguard_headers() -> dict[str, str]:
    return {"Authorization": f"Basic {AUTH_TOKEN}"}


def rewrites() -> set[tuple[str, str]]:
    result = request_json(
        f"{ADGUARD_URL}/control/rewrite/list", headers=adguard_headers()
    )
    if not isinstance(result, list):
        raise RuntimeError("AdGuard returned an unexpected rewrite response")

    records: set[tuple[str, str]] = set()
    for item in result:
        if not isinstance(item, dict):
            continue
        domain = _clean(item.get("domain", ""))
        answer = str(item.get("answer", "")).strip()
        if domain and answer:
            records.add((domain, answer))
    return records


def add_rewrite(domain: str, answer: str) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/add",
        method="POST",
        body={"domain": domain, "answer": answer},
        headers=adguard_headers(),
    )
    LOG.info("added rewrite %s -> %s", domain, answer)


def delete_rewrite(domain: str, answer: str) -> None:
    request_json(
        f"{ADGUARD_URL}/control/rewrite/delete",
        method="POST",
        body={"domain": domain, "answer": answer},
        headers=adguard_headers(),
    )
    LOG.info("deleted rewrite %s -> %s", domain, answer)


def load_managed_records() -> set[tuple[str, str]]:
    """Load exact records previously created by this companion."""
    try:
        result = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return set()
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {STATE_FILE}: {error}") from error

    if not isinstance(result, list):
        raise RuntimeError(f"{STATE_FILE} must contain a JSON array")

    managed: set[tuple[str, str]] = set()
    for item in result:
        if not isinstance(item, dict):
            continue
        domain = _clean(item.get("domain", ""))
        answer = str(item.get("answer", "")).strip()
        if domain and answer:
            managed.add((domain, answer))
    return managed


def save_managed_records(records: set[tuple[str, str]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    payload = [
        {"domain": domain, "answer": answer}
        for domain, answer in sorted(records)
    ]

    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(STATE_FILE)


def reconcile() -> None:
    LOG.info("refreshing Traefik routers")

    routers = traefik_routers()
    containers = docker_containers()
    desired = desired_records(routers, containers)
    existing = rewrites()
    managed = load_managed_records()

    LOG.info(
        "Traefik routers: %d, desired DNS records: %d, "
        "existing AdGuard rewrites: %d, managed records: %d",
        len(routers),
        len(desired),
        len(existing),
        len(managed),
    )

    # Create missing desired records. Unowned existing records are left alone.
    for domain, answer in sorted(desired):
        record = (domain, answer)

        if record in managed:
            if record not in existing:
                LOG.info(
                    "recreating missing managed rewrite %s -> %s", domain, answer
                )
                add_rewrite(domain, answer)
                existing.add(record)
            continue

        if record in existing:
            LOG.info(
                "preserving existing unowned rewrite %s -> %s", domain, answer
            )
            continue

        LOG.info("creating managed rewrite %s -> %s", domain, answer)
        add_rewrite(domain, answer)
        existing.add(record)
        managed.add(record)

    # Remove stale records that WE own. Manual records are never deleted.
    for domain, answer in sorted(managed - desired):
        record = (domain, answer)

        if record not in existing:
            LOG.info("managed rewrite already absent %s -> %s", domain, answer)
            managed.discard(record)
            continue

        LOG.info("removing stale managed rewrite %s -> %s", domain, answer)
        delete_rewrite(domain, answer)
        existing.discard(record)
        managed.discard(record)

    save_managed_records(managed)

    LOG.info(
        "reconciled %d desired DNS record(s), %d managed record(s)",
        len(desired),
        len(managed),
    )


def request_status(url: str, *, headers: dict[str, str] | None = None) -> int:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except urllib.error.URLError as error:
        raise RuntimeError(f"request to {url} failed: {error}") from error


def healthcheck() -> None:
    traefik_status = request_status(TRAEFIK_API_URL)
    if traefik_status != 200:
        raise RuntimeError(f"Traefik healthcheck returned HTTP {traefik_status}")

    adguard_status = request_status(
        f"{ADGUARD_URL}/control/status", headers=adguard_headers()
    )
    if adguard_status != 200:
        raise RuntimeError(f"AdGuard healthcheck returned HTTP {adguard_status}")

    print("OK", flush=True)


def stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def main() -> None:
    for name in ("ADGUARD_URL", "ADGUARD_USERNAME", "ADGUARD_PASSWORD"):
        required_env(name)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    LOG.info("AdGuard DNS companion started")
    LOG.info("Traefik API: %s", TRAEFIK_API_URL)
    LOG.info("AdGuard URL: %s", ADGUARD_URL)
    LOG.info("Poll interval: %ss", POLL_INTERVAL)
    LOG.info("State file: %s", STATE_FILE)

    while not STOP:
        try:
            reconcile()
        except (OSError, RuntimeError, ValueError, urllib.error.URLError) as error:
            LOG.error("reconciliation failed: %s", error)

        for _ in range(POLL_INTERVAL):
            if STOP:
                break
            time.sleep(1)

    LOG.info("AdGuard DNS companion stopped")


if __name__ == "__main__":
    if "--healthcheck" in sys.argv[1:]:
        try:
            for name in ("ADGUARD_URL", "ADGUARD_USERNAME", "ADGUARD_PASSWORD"):
                required_env(name)
            healthcheck()
        except Exception as error:
            LOG.error("healthcheck failed: %s", error)
            sys.exit(1)
        sys.exit(0)

    try:
        main()
    except Exception as error:
        LOG.error("startup failed: %s", error)
        sys.exit(1)
