"""Durable Redis Streams boundary for out-of-band anomaly evaluation."""

from __future__ import annotations

import json
import os
import socket
from functools import lru_cache
from typing import Any, cast

import redis

STREAM = "abx:alert_jobs"
GROUP = "abx-alert-rules"


@lru_cache(maxsize=1)
def redis_client() -> Any:
    return redis.Redis.from_url(
        os.environ.get("ABX_REDIS_URL", "redis://localhost:6379"),
        decode_responses=True,
    )


def enqueue_alerts(tenant_id: str, event_ids: list[str]) -> str:
    return str(redis_client().xadd(
        STREAM, {"tenant_id": tenant_id, "event_ids": json.dumps(event_ids)},
    ))


def process_job(fields: dict[str, str]) -> int:
    # Imported only by the deployed worker. The pure engine remains reusable
    # without app/storage dependencies.
    from abx_api.alerts import evaluate_event_ids

    event_ids = json.loads(fields["event_ids"])
    if not isinstance(event_ids, list) or not all(isinstance(value, str) for value in event_ids):
        raise ValueError("invalid event id batch")
    return evaluate_event_ids(fields["tenant_id"], event_ids)


def ensure_group(client: Any) -> None:
    try:
        client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def run_worker(client: Any | None = None, *, once: bool = False) -> int:
    stream_client = client or redis_client()
    ensure_group(stream_client)
    consumer = f"{socket.gethostname()}-{os.getpid()}"
    completed = 0
    while True:
        messages = cast(
            list[tuple[str, list[tuple[str, dict[str, str]]]]],
            stream_client.xreadgroup(
                GROUP, consumer, {STREAM: ">"}, count=1, block=1000 if once else 5000,
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
