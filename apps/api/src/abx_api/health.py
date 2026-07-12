"""Process liveness and durable dependency readiness probes."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from abx_api.scan_queue import redis_client
from abx_api.settings import settings
from abx_api.store import ch_client, pg_pool, s3_client

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness only: the process can serve requests."""
    return {"status": "ok"}


@router.get("/readyz")
def readyz() -> JSONResponse:
    """Readiness: every durable dependency needed by normal traffic responds."""
    checks: dict[str, Callable[[], bool]] = {
        "postgres": check_postgres,
        "clickhouse": check_clickhouse,
        "redis": check_redis,
        "object_store": check_object_store,
    }
    dependencies = {
        name: "ok" if _safe_check(check) else "unavailable"
        for name, check in checks.items()
    }
    ready = all(value == "ok" for value in dependencies.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not_ready", "dependencies": dependencies},
    )


def _safe_check(check: Callable[[], bool]) -> bool:
    try:
        return check()
    except Exception:
        return False


def check_postgres() -> bool:
    with pg_pool().connection(timeout=2) as conn:
        row = conn.execute("SELECT 1").fetchone()
    return row == (1,)


def check_clickhouse() -> bool:
    rows = ch_client().query(
        "SELECT 1", settings={"max_execution_time": 2}
    ).result_rows
    return bool(rows) and cast(int, rows[0][0]) == 1


def check_redis() -> bool:
    return bool(redis_client().ping())


def check_object_store() -> bool:
    s3 = s3_client()
    s3.head_bucket(Bucket=settings.payload_bucket)
    s3.head_bucket(Bucket=settings.anchor_bucket)
    return True
