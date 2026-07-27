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


def test_worker_treats_idle_timeout_as_empty_poll() -> None:
    client = FakeRedis(JOB)
    client.xreadgroup = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        worker.redis.TimeoutError("idle")
    )
    assert worker.run_worker(client, once=True) == 0


def test_worker_resolves_gcp_credentials_only_inside_worker(monkeypatch) -> None:
    fake_client = object()
    seen: list[tuple[str, str, object]] = []
    monkeypatch.setattr(worker, "GcpClient", lambda: fake_client)
    monkeypatch.setattr(
        worker,
        "run_gcp_scan",
        lambda tenant, project, client: seen.append((tenant, project, client)),
    )
    job = {"provider": "gcp", "tenant_id": "tenant", "project_id": "pocketos-prod"}
    worker.process_job(job)
    assert seen == [("tenant", "pocketos-prod", fake_client)]
    assert set(job) == {"provider", "tenant_id", "project_id"}
