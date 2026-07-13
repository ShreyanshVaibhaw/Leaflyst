"""Consume alert jobs beside the API persistence layer they require."""

from __future__ import annotations

import json
import os
import socket
from typing import Any, cast

import redis
from abx_rules.queue import GROUP, STREAM, redis_client

from abx_api.alerts import evaluate_event_ids


def process_job(fields: dict[str, str]) -> int:
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
        try:
            messages = cast(
                list[tuple[str, list[tuple[str, dict[str, str]]]]],
                stream_client.xreadgroup(
                    GROUP, consumer, {STREAM: ">"}, count=1, block=1000 if once else 5000,
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
