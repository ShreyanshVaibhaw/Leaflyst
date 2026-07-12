from abx_api import health
from abx_api.main import app
from conftest import requires_stack
from fastapi.testclient import TestClient


def test_healthz() -> None:
    resp = TestClient(app).get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@requires_stack
def test_readyz_checks_all_durable_dependencies() -> None:
    resp = TestClient(app).get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ready",
        "dependencies": {
            "postgres": "ok",
            "clickhouse": "ok",
            "redis": "ok",
            "object_store": "ok",
        },
    }


def test_readyz_returns_generic_failure_without_leaking_details(monkeypatch) -> None:
    monkeypatch.setattr(health, "check_postgres", lambda: False)
    resp = TestClient(app).get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["dependencies"]["postgres"] == "unavailable"
    assert "postgresql://" not in resp.text
