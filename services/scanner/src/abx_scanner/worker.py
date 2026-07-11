"""Redis Streams scanner worker.

Run with: ``uv run python -m abx_scanner.worker``. Jobs contain identifiers
only; provider credentials are read from the worker environment.
"""

from __future__ import annotations

import os
import socket
from typing import Any, cast

import redis

from abx_scanner.gh_auth import installation_token, now_epoch
from abx_scanner.gh_client import GitHubClient
from abx_scanner.scan import run_github_scan

STREAM = "abx:scan_jobs"
GROUP = "abx-scanners"


def _env(name: str) -> str:
    value = os.environ.get(name, "").replace("\\n", "\n")
    if not value:
        raise RuntimeError(f"{name} is required for GitHub scan jobs")
    return value


def process_job(fields: dict[str, str]) -> None:
    provider = fields.get("provider")
    if provider != "github":
        raise ValueError(f"unsupported scan provider: {provider}")
    app_id = _env("ABX_GITHUB_APP_ID")
    private_key = _env("ABX_GITHUB_PRIVATE_KEY")
    token = installation_token(
        app_id, private_key, fields["installation_id"], now_epoch()
    )
    run_github_scan(fields["tenant_id"], fields["org"], GitHubClient(token))


def ensure_group(client: Any) -> None:
    try:
        client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def run_worker(client: Any | None = None, *, once: bool = False) -> int:
    stream_client: Any = client or redis.Redis.from_url(
        os.environ.get("ABX_REDIS_URL", "redis://localhost:6379"), decode_responses=True
    )
    ensure_group(stream_client)
    consumer = f"{socket.gethostname()}-{os.getpid()}"
    completed = 0
    while True:
        messages = cast(
            list[tuple[str, list[tuple[str, dict[str, str]]]]],
            stream_client.xreadgroup(
                GROUP, consumer, {STREAM: ">"}, count=1, block=1000 if once else 5000
            ),
        )
        if not messages:
            if once:
                return completed
            continue
        for _stream, entries in messages:
            for message_id, fields in entries:
                try:
                    process_job(fields)
                except Exception as exc:
                    stream_client.xadd(
                        f"{STREAM}:failed",
                        {**fields, "source_message_id": message_id, "error": str(exc)[:500]},
                    )
                else:
                    completed += 1
                finally:
                    stream_client.xack(STREAM, GROUP, message_id)
        if once:
            return completed


def main() -> int:
    run_worker()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
