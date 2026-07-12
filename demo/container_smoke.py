"""Build and smoke the production API/worker and web container artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.request
import uuid
from collections.abc import Sequence

PYTHON_IMAGE = "agentblackbox-python:release-smoke"
WEB_IMAGE = "agentblackbox-web:release-smoke"


def run(command: Sequence[str], *, capture: bool = False) -> str:
    result = subprocess.run(command, check=True, capture_output=capture, text=True)
    return result.stdout.strip() if capture else ""


def image_config(image: str) -> dict[str, object]:
    raw = run(["docker", "image", "inspect", image, "--format", "{{json .Config}}"], capture=True)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"invalid image configuration for {image}")
    return parsed


def wait_healthy(container: str, timeout: int = 75) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
            capture=True,
        )
        if status == "healthy":
            return
        if status == "unhealthy":
            raise RuntimeError(f"{container} became unhealthy")
        time.sleep(2)
    raise RuntimeError(f"{container} did not become healthy")


def assert_safe_image(image: str) -> None:
    config = image_config(image)
    user = str(config.get("User") or "")
    if not user or user in {"0", "root", "0:0"}:
        raise RuntimeError(f"{image} runs as root")
    environment = [str(value) for value in config.get("Env", [])]  # type: ignore[union-attr]
    forbidden = (
        "ABX_ADMIN_KEY=",
        "ABX_GITHUB_PRIVATE_KEY=",
        "ABX_S3_SECRET_KEY=",
        "ABX_TENANT_COOKIE_SECRET=",
    )
    if any(value.startswith(forbidden) for value in environment):
        raise RuntimeError(f"{image} contains a configured secret")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if not args.skip_build:
        run([
            "docker", "build", "--pull=false", "-f", "infra/docker/python.Dockerfile",
            "-t", PYTHON_IMAGE, ".",
        ])
        run([
            "docker", "build", "--pull=false", "-f", "infra/docker/web.Dockerfile",
            "-t", WEB_IMAGE, ".",
        ])
    assert_safe_image(PYTHON_IMAGE)
    assert_safe_image(WEB_IMAGE)

    suffix = uuid.uuid4().hex[:8]
    api = f"abx-api-{suffix}"
    web = f"abx-web-{suffix}"
    try:
        run([
            "docker", "run", "-d", "--rm", "--name", api, "-p", "18432:8000",
            "-e", "ABX_ENV=staging", PYTHON_IMAGE,
        ])
        run([
            "docker", "run", "-d", "--rm", "--name", web, "-p", "18433:3000",
            "-e", "ABX_API_URL=http://host.docker.internal:18432",
            "-e", "ABX_TENANT_COOKIE_SECRET=container-smoke-cookie-secret-123456",
            WEB_IMAGE,
        ])
        wait_healthy(api)
        wait_healthy(web)
        with urllib.request.urlopen("http://127.0.0.1:18432/healthz", timeout=5) as response:
            if json.load(response) != {"status": "ok"}:
                raise RuntimeError("API health response is invalid")
        with urllib.request.urlopen("http://127.0.0.1:18433/security", timeout=5) as response:
            if response.status != 200:
                raise RuntimeError("web security page is unavailable")
        run([
            "docker", "exec", web, "sh", "-c",
            "test -n \"$(find /ms-playwright -type f -name chrome -perm -111 -print -quit)\" "
            "&& test -n \"$(find /app/.next/node_modules -name 'playwright-*' -print -quit)\"",
        ])
    finally:
        subprocess.run(
            ["docker", "rm", "-f", api, web],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    print("OK: non-root API/worker and Next.js+Chromium release images are healthy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
