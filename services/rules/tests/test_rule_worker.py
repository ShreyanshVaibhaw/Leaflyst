"""Redis polling behavior for the alert worker."""

from __future__ import annotations

from typing import Any

from abx_rules import worker


class TimeoutRedis:
    def xgroup_create(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def xreadgroup(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        raise worker.redis.TimeoutError("idle")


def test_worker_treats_idle_timeout_as_empty_poll() -> None:
    assert worker.run_worker(TimeoutRedis(), once=True) == 0
