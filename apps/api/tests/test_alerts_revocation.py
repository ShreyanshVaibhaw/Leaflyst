"""Cross-product anomaly detection and impact-gated revocation safety."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from abx_api import alerts as alert_api
from abx_api import revocation
from abx_api.alert_worker import process_job
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client
from conftest import requires_stack
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

pytestmark = requires_stack
client = TestClient(app)
ADMIN = {"X-Abx-Admin-Key": settings.admin_key}


def _event(session: str, operation: str, credential: str | None, refs: list[str]) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()), "agent_id": "staging-bot", "session_id": session,
        "seq": 0, "ts": datetime.now(UTC).isoformat(), "source": "mcp_tap",
        "event_type": "tool_call",
        "operation": {"name": operation, "provider": "aws", "target": "orders",
                      "outcome": "success", "duration_ms": 4},
        "credential_ref": credential, "resource_refs": refs,
    }


def _seed_credential(tenant_id: str, *, warm: bool = False) -> tuple[str, str]:
    fingerprint = "AKIA1234567890ABCDEF"
    used = datetime.now(UTC) if warm else datetime.now(UTC) - timedelta(days=45)
    with psycopg.connect(settings.pg_dsn) as conn:
        principal = conn.execute(
            "INSERT INTO principals (tenant_id, provider, kind, external_id) "
            "VALUES (%s,'aws','iam_user','arn:aws:iam::1:user/staging-bot') RETURNING id",
            (tenant_id,),
        ).fetchone()[0]
        credential_id = str(conn.execute(
            "INSERT INTO credentials (tenant_id, provider, kind, fingerprint, "
            "owner_principal, last_used_at) VALUES (%s,'aws','access_key',%s,%s,%s) "
            "RETURNING id", (tenant_id, fingerprint, principal, used),
        ).fetchone()[0])
    return credential_id, fingerprint


def test_scanner_flagged_credential_fires_deduped_live_alert(
    tenant: tuple[str, str],
) -> None:
    tenant_id, token = tenant
    credential_id, fingerprint = _seed_credential(tenant_id)
    with psycopg.connect(settings.pg_dsn) as conn:
        conn.execute(
            "INSERT INTO scan_runs (tenant_id, provider, status, finished_at) "
            "VALUES (%s,'aws','succeeded',now())", (tenant_id,),
        )
        conn.execute(
            "INSERT INTO findings (tenant_id, finding_type, natural_key, severity, "
            "credential_id, evidence) VALUES (%s,'over_privileged','test:flag','critical',%s,%s)",
            (tenant_id, credential_id, Jsonb({"fingerprint": fingerprint})),
        )
    for seq in range(2):
        event = _event(f"danger-{seq}", "delete production database", fingerprint,
                       ["aws:rds:production"])
        response = client.post(
            "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
            json={"events": [event]},
        )
        assert response.status_code == 200, response.text
        process_job({"tenant_id": tenant_id, "event_ids": json.dumps([event["event_id"]])})
    alerts = client.get("/v1/alerts", params={"tenant_id": tenant_id}, headers=ADMIN).json()
    by_rule = {alert["rule_id"]: alert for alert in alerts}
    assert "destructive_operation" in by_rule
    assert "credential_outside_scope" in by_rule
    assert by_rule["credential_outside_scope"]["hit_count"] == 2
    assert by_rule["credential_outside_scope"]["session_id"] == "danger-1"


def test_new_agent_has_no_history_false_positive(tenant: tuple[str, str]) -> None:
    tenant_id, token = tenant
    event = _event("first-session", "read file", None, [])
    response = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [event]},
    )
    assert response.status_code == 200
    process_job({"tenant_id": tenant_id, "event_ids": json.dumps([event["event_id"]])})
    assert client.get(
        "/v1/alerts", params={"tenant_id": tenant_id}, headers=ADMIN,
    ).json() == []


def test_alert_queue_failure_never_blocks_recording(
    tenant: tuple[str, str], monkeypatch: Any,
) -> None:
    import abx_rules.queue

    tenant_id, token = tenant
    event = _event("queue-down", "read file", None, [])
    monkeypatch.setattr(
        abx_rules.queue, "enqueue_alerts",
        lambda *_args: (_ for _ in ()).throw(ConnectionError("redis down")),
    )
    response = client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [event]},
    )
    assert response.status_code == 200
    stored = ch_client().query(
        "SELECT count() FROM events WHERE tenant_id=%(tenant)s AND event_id=%(event)s",
        parameters={"tenant": tenant_id, "event": event["event_id"]},
    ).result_rows[0][0]
    assert stored == 1


def test_tool_inventory_drift_waits_for_second_session(
    tenant: tuple[str, str],
) -> None:
    tenant_id, token = tenant
    first = _event("tools-a", "tools/list", None, ["abx:tool-inventory:aaa"])
    second = _event("tools-b", "tools/list", None, ["abx:tool-inventory:bbb"])
    assert client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [first]},
    ).status_code == 200
    process_job({"tenant_id": tenant_id, "event_ids": json.dumps([first["event_id"]])})
    assert client.get(
        "/v1/alerts", params={"tenant_id": tenant_id}, headers=ADMIN,
    ).json() == []
    assert client.post(
        "/v1/ingest", headers={"Authorization": f"Bearer {token}"},
        json={"events": [second]},
    ).status_code == 200
    process_job({"tenant_id": tenant_id, "event_ids": json.dumps([second["event_id"]])})
    found = client.get(
        "/v1/alerts", params={"tenant_id": tenant_id}, headers=ADMIN,
    ).json()
    assert [alert["rule_id"] for alert in found] == ["tool_inventory_drift"]


class FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_slack_and_resend_dispatch_keep_secrets_out_of_storage(
    tenant: tuple[str, str], monkeypatch: Any,
) -> None:
    tenant_id, _token = tenant
    with psycopg.connect(settings.pg_dsn) as conn:
        conn.execute(
            "INSERT INTO alert_channels (tenant_id, kind, target) VALUES "
            "(%s,'slack',''),(%s,'email','security@example.com')",
            (tenant_id, tenant_id),
        )
    configured = replace(
        settings, slack_webhook_url="https://hooks.slack.com/services/secret",
        resend_api_key="re_secret", alert_email_from="alerts@example.com",
    )
    monkeypatch.setattr(alert_api, "settings", configured)
    requests: list[Any] = []

    def fake_open(request: Any, timeout: int) -> FakeResponse:
        assert timeout == 10
        requests.append(request)
        return FakeResponse()

    monkeypatch.setattr(alert_api.urllib.request, "urlopen", fake_open)
    status = alert_api.dispatch_alert(tenant_id, "alert-id", "Danger", "session")
    assert status == {"slack": "sent", "email": "sent"}
    assert [request.full_url for request in requests] == [
        "https://hooks.slack.com/services/secret", "https://api.resend.com/emails",
    ]
    with psycopg.connect(settings.pg_dsn) as conn:
        stored = str(conn.execute(
            "SELECT json_agg(alert_channels) FROM alert_channels WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()[0])
    assert "hooks.slack.com" not in stored
    assert "re_secret" not in stored


class FakeRevokeAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute(self, action: str, credential: dict[str, Any]) -> None:
        self.calls.append((action, credential))


def test_cold_key_deactivates_with_confirmation_and_chain_audit(
    tenant: tuple[str, str], monkeypatch: Any,
) -> None:
    tenant_id, _token = tenant
    credential_id, fingerprint = _seed_credential(tenant_id)
    fake = FakeRevokeAdapter()
    monkeypatch.setattr(revocation, "adapter_for", lambda _provider: fake)
    monkeypatch.setattr(revocation, "settings", replace(
        settings, aws_revoke_access_key_id="write-only-id",
        aws_revoke_secret_access_key="write-only-secret",
    ))
    preview = client.get(
        f"/v1/revocation/{credential_id}/impact",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    ).json()
    assert preview["cold"] is True
    assert preview["one_click"] is True
    assert preview["next_action"] == "deactivate"
    started = time.perf_counter()
    result = client.post(
        f"/v1/revocation/{credential_id}", params={"tenant_id": tenant_id}, headers=ADMIN,
        json={"confirmation": fingerprint, "action": "deactivate"},
    )
    assert time.perf_counter() - started < 5
    assert result.status_code == 200, result.text
    assert result.json()["credential_status"] == "inactive"
    assert fake.calls[0][0] == "deactivate"
    audit = ch_client().query(
        "SELECT source, event_type, credential_ref FROM events WHERE tenant_id=%(tenant)s "
        "AND event_type='credential_revocation'",
        parameters={"tenant": tenant_id},
    ).result_rows
    assert audit == [("admin_api", "credential_revocation", fingerprint)]


def test_warm_key_is_guided_only(tenant: tuple[str, str], monkeypatch: Any) -> None:
    tenant_id, _token = tenant
    credential_id, fingerprint = _seed_credential(tenant_id, warm=True)
    fake = FakeRevokeAdapter()
    monkeypatch.setattr(revocation, "adapter_for", lambda _provider: fake)
    monkeypatch.setattr(revocation, "settings", replace(
        settings, aws_revoke_access_key_id="write-only-id",
        aws_revoke_secret_access_key="write-only-secret",
    ))
    preview = client.get(
        f"/v1/revocation/{credential_id}/impact",
        params={"tenant_id": tenant_id}, headers=ADMIN,
    ).json()
    assert preview["cold"] is False
    assert preview["one_click"] is False
    result = client.post(
        f"/v1/revocation/{credential_id}", params={"tenant_id": tenant_id}, headers=ADMIN,
        json={"confirmation": fingerprint, "action": "deactivate"},
    )
    assert result.status_code == 409
    assert fake.calls == []


def test_failed_provider_action_is_also_chain_audited(
    tenant: tuple[str, str], monkeypatch: Any,
) -> None:
    tenant_id, _token = tenant
    credential_id, fingerprint = _seed_credential(tenant_id)

    class FailingAdapter:
        def execute(self, _action: str, _credential: dict[str, Any]) -> None:
            raise TimeoutError("provider timeout")

    monkeypatch.setattr(revocation, "adapter_for", lambda _provider: FailingAdapter())
    monkeypatch.setattr(revocation, "settings", replace(
        settings, aws_revoke_access_key_id="write-only-id",
        aws_revoke_secret_access_key="write-only-secret",
    ))
    response = client.post(
        f"/v1/revocation/{credential_id}", params={"tenant_id": tenant_id}, headers=ADMIN,
        json={"confirmation": fingerprint, "action": "deactivate"},
    )
    assert response.status_code == 502
    audit = ch_client().query(
        "SELECT op_outcome FROM events WHERE tenant_id=%(tenant)s "
        "AND event_type='credential_revocation'",
        parameters={"tenant": tenant_id},
    ).result_rows
    assert audit == [("error",)]


def test_github_revoker_uses_only_documented_write_endpoints(monkeypatch: Any) -> None:
    configured = replace(settings, github_revoke_token="write-only-token")
    monkeypatch.setattr(revocation, "settings", configured)
    requests: list[Any] = []

    def fake_open(request: Any, timeout: int) -> FakeResponse:
        assert timeout == 10
        requests.append(request)
        return FakeResponse(204)

    monkeypatch.setattr(revocation.urllib.request, "urlopen", fake_open)
    adapter = revocation.GitHubRevokeAdapter()
    adapter.execute("revoke", {
        "fingerprint": "pat:42", "org": "acme", "owner": "", "kind": "fine_grained_pat",
    })
    adapter.execute("revoke", {
        "fingerprint": "deploykey:acme/repo:7", "org": "acme", "owner": "",
        "kind": "deploy_key",
    })
    assert [(request.method, request.full_url) for request in requests] == [
        ("POST", "https://api.github.com/orgs/acme/personal-access-tokens/42"),
        ("DELETE", "https://api.github.com/repos/acme/repo/keys/7"),
    ]
    assert json.loads(requests[0].data) == {"action": "revoke"}
