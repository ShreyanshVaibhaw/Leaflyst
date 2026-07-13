"""Durable queue publication shared by ingest and the alert worker."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

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
    return str(
        redis_client().xadd(
            STREAM,
            {"tenant_id": tenant_id, "event_ids": json.dumps(event_ids)},
        )
    )
