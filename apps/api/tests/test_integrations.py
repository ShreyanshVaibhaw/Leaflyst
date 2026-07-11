"""GitHub App connection state and setup callback tests."""

from __future__ import annotations

from dataclasses import replace

import psycopg
import pytest
from abx_api import integrations
from abx_api.main import app
from abx_api.settings import settings
from conftest import requires_stack
from fastapi import HTTPException
from fastapi.testclient import TestClient

pytestmark = requires_stack
client = TestClient(app)


def test_signed_state_round_trip_and_rejects_tampering() -> None:
    state = integrations.make_state("tenant-one", now=100)
    assert integrations.parse_state(state, now=101) == "tenant-one"
    with pytest.raises(HTTPException):
        integrations.parse_state(state + "x", now=101)
    with pytest.raises(HTTPException):
        integrations.parse_state(state, now=1001)


def test_setup_validates_persists_and_queues(monkeypatch, tenant: tuple[str, str]) -> None:
    tenant_id, _token = tenant
    configured = replace(
        settings,
        github_app_id="123",
        github_private_key="private-key",
        github_app_slug="agentblackbox-test",
        web_url="http://dashboard.test",
    )
    monkeypatch.setattr(integrations, "settings", configured)
    monkeypatch.setattr(
        integrations,
        "installation_details",
        lambda *_args: {
            "target_type": "Organization",
            "account": {"login": "acme"},
            "repository_selection": "all",
        },
    )
    queued: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        integrations,
        "enqueue_github_scan",
        lambda tid, iid, org: queued.append((tid, iid, org)) or "1-0",
    )
    state = integrations.make_state(tenant_id)
    response = client.get(
        "/v1/integrations/github/setup",
        params={"installation_id": "456", "state": state},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("/integrations?github=connected&org=acme")
    assert queued == [(tenant_id, "456", "acme")]
    with psycopg.connect(settings.pg_dsn) as conn:
        row = conn.execute(
            "SELECT external_id, account_login FROM integration_connections "
            "WHERE tenant_id = %s", (tenant_id,)
        ).fetchone()
        assert row == ("456", "acme")
        conn.execute("DELETE FROM integration_connections WHERE tenant_id = %s", (tenant_id,))
        conn.commit()


def test_setup_rejects_non_organization(monkeypatch, tenant: tuple[str, str]) -> None:
    tenant_id, _token = tenant
    monkeypatch.setattr(
        integrations,
        "settings",
        replace(settings, github_app_id="123", github_private_key="private-key"),
    )
    monkeypatch.setattr(
        integrations,
        "installation_details",
        lambda *_args: {"target_type": "User", "account": {"login": "alice"}},
    )
    response = client.get(
        "/v1/integrations/github/setup",
        params={"installation_id": "789", "state": integrations.make_state(tenant_id)},
    )
    assert response.status_code == 400
