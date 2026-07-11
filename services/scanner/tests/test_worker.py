"""Redis job delivery behavior for the scanner worker."""

from __future__ import annotations

from typing import Any

from abx_scanner import worker


class FakeRedis:
    def __init__(self, fields: dict[str, str]) -> None:
        self.fields = fields
        self.acked: list[str] = []
        self.failed: list[dict[str, str]] = []

    def xgroup_create(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def xreadgroup(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        return [(worker.STREAM, [("1-0", self.fields)])]

    def xack(self, _stream: str, _group: str, message_id: str) -> None:
        self.acked.append(message_id)

    def xadd(self, _stream: str, fields: dict[str, str]) -> str:
        self.failed.append(fields)
        return "2-0"


JOB = {
    "provider": "github",
    "tenant_id": "tenant",
    "installation_id": "42",
    "org": "acme",
}


def test_worker_processes_and_acknowledges(monkeypatch) -> None:
    client = FakeRedis(JOB)
    seen: list[dict[str, str]] = []
    monkeypatch.setattr(worker, "process_job", lambda fields: seen.append(fields))
    assert worker.run_worker(client, once=True) == 1
    assert seen == [JOB]
    assert client.acked == ["1-0"]
    assert client.failed == []


def test_worker_dead_letters_failed_job(monkeypatch) -> None:
    client = FakeRedis(JOB)

    def fail(_fields: dict[str, str]) -> None:
        raise RuntimeError("scan failed")

    monkeypatch.setattr(worker, "process_job", fail)
    assert worker.run_worker(client, once=True) == 0
    assert client.acked == ["1-0"]
    assert client.failed[0]["error"] == "scan failed"
