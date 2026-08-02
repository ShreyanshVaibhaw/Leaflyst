"""Redis Streams scanner worker.

Run with: ``uv run python -m abx_scanner.worker``. Jobs contain identifiers
only; provider credentials are read from the worker environment.
"""

from __future__ import annotations

import os
import socket
from typing import Any, cast

import redis

from abx_scanner.azure_client import AzureClient
from abx_scanner.gcp_client import GcpClient
from abx_scanner.gh_auth import installation_token, now_epoch
from abx_scanner.gh_client import GitHubClient
from abx_scanner.scan import (
    run_azure_scan,
    run_gcp_scan,
    run_github_scan,
    run_slack_scan,
    run_workspace_scan,
)
from abx_scanner.slack_client import SlackClient
from abx_scanner.workspace_client import WorkspaceClient

STREAM = "abx:scan_jobs"
GROUP = "abx-scanners"


def _env(name: str) -> str:
    value = os.environ.get(name, "").replace("\\n", "\n")
    if not value:
        raise RuntimeError(f"{name} is required for GitHub scan jobs")
    return value


def process_job(fields: dict[str, str]) -> None:
    provider = fields.get("provider")
    if provider == "github":
        app_id = _env("ABX_GITHUB_APP_ID")
        private_key = _env("ABX_GITHUB_PRIVATE_KEY")
        token = installation_token(
            app_id, private_key, fields["installation_id"], now_epoch()
        )
        run_github_scan(fields["tenant_id"], fields["org"], GitHubClient(token))
        return
    if provider == "gcp":
        run_gcp_scan(fields["tenant_id"], fields["project_id"], GcpClient())
        return
    if provider == "azure":
        run_azure_scan(
            fields["tenant_id"], fields["azure_tenant"], fields["subscription_id"],
            AzureClient(),
        )
        return
    if provider == "workspace":
        run_workspace_scan(fields["tenant_id"], fields["domain"], WorkspaceClient())
        return
    if provider == "slack":
        run_slack_scan(fields["tenant_id"], SlackClient(_env("ABX_SLACK_ADMIN_TOKEN")))
        return
    raise ValueError(f"unsupported scan provider: {provider}")


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
        try:
            messages = cast(
                list[tuple[str, list[tuple[str, dict[str, str]]]]],
                stream_client.xreadgroup(
                    GROUP, consumer, {STREAM: ">"}, count=1, block=1000 if once else 5000
                ),
            )
        except redis.TimeoutError:
            if once:
                return completed
            continue
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
