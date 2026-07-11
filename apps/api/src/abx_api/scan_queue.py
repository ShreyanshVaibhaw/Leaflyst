"""Small Redis Streams boundary between the app API and scanner workers."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import redis

from abx_api.settings import settings

SCAN_STREAM = "abx:scan_jobs"


@lru_cache(maxsize=1)
def redis_client() -> Any:
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def enqueue_github_scan(tenant_id: str, installation_id: str, org: str) -> str:
    job_id = redis_client().xadd(
        SCAN_STREAM,
        {
            "provider": "github",
            "tenant_id": tenant_id,
            "installation_id": installation_id,
            "org": org,
        },
    )
    return str(job_id)
