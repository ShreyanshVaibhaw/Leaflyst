"""Roles, scoped read tokens, and the tenant-isolation audit (plan2 phase 23).

Two properties carry this phase:

1. A scoped read token BINDS its tenant. The shared operator key it replaces
   carries no tenant binding, so a caller holding it supplies whatever
   tenant_id it likes. Binding makes cross-tenant reads impossible by
   construction rather than by every route remembering to check.

2. The auditor role can export everything and change nothing. An external
   assessor who *could* alter configuration undermines the independence of the
   assessment they are performing, so it has to be a real role rather than an
   admin account plus a promise.
"""

from __future__ import annotations

import uuid
from dataclasses import replace

import pytest
from abx_api.main import app
from abx_api.rbac import (
    ROLE_CAPABILITIES,
    Capability,
    Principal,
    new_read_token,
    resolve_principal,
)
from abx_api.store import pg_pool
from conftest import requires_stack
from fastapi import HTTPException
from fastapi.testclient import TestClient

ADMIN = {"X-Abx-Admin-Key": "dev-admin-key"}


def mint(tenant_id: str, role: str) -> str:
    response = TestClient(app).post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": f"{role}-token", "role": role},
        headers=ADMIN,
    )
    assert response.status_code == 200, response.text
    return str(response.json()["token"])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# -- capability model ----------------------------------------------------------

def test_roles_are_not_a_ladder() -> None:
    """An auditor exports evidence a responder cannot; a responder revokes a
    credential an auditor must not touch. Ranking them would be wrong."""
    responder = ROLE_CAPABILITIES["responder"]
    auditor = ROLE_CAPABILITIES["auditor"]
    assert Capability.REVOKE in responder and Capability.REVOKE not in auditor
    assert Capability.EXPORT_EVIDENCE in auditor
    assert Capability.EXPORT_EVIDENCE not in responder


def test_only_admin_may_configure() -> None:
    for role in ("viewer", "responder", "auditor"):
        assert Capability.CONFIGURE not in ROLE_CAPABILITIES[role]
    assert Capability.CONFIGURE in ROLE_CAPABILITIES["admin"]


def test_every_role_may_read() -> None:
    assert all(Capability.READ in caps for caps in ROLE_CAPABILITIES.values())


def test_an_unknown_role_grants_nothing() -> None:
    """Fail closed: a role that is not in the table has no capabilities."""
    stranger = Principal(role="superuser", tenant_id="t1")
    assert stranger.capabilities == frozenset()
    assert not stranger.may(Capability.READ)


def test_an_unbound_principal_may_act_on_any_tenant() -> None:
    operator = Principal(role="admin", tenant_id=None)
    assert operator.scoped_to("anything")


def test_a_bound_principal_is_confined_to_its_tenant() -> None:
    bound = Principal(role="viewer", tenant_id="tenant-a")
    assert bound.scoped_to("tenant-a")
    assert not bound.scoped_to("tenant-b")


def test_unauthenticated_is_refused() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_principal("", "")
    assert exc.value.status_code == 401


def test_a_wrong_admin_key_is_refused() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_principal("not-the-key", "")
    assert exc.value.status_code == 401


def test_read_tokens_are_stored_only_as_hashes() -> None:
    token, token_hash = new_read_token()
    assert token.startswith("abx_read_")
    assert token not in token_hash


# -- end to end ----------------------------------------------------------------

@requires_stack
def test_a_scoped_token_cannot_read_another_tenant(tenant) -> None:
    """The attack the shared key allowed. 404 rather than 403 so it cannot be
    used to probe which tenant ids exist."""
    tenant_id, _ = tenant
    client = TestClient(app)
    with pg_pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"other-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
    other_tenant = str(row[0])

    token = mint(tenant_id, "viewer")
    mine = client.get(f"/v1/dashboard/overview?tenant_id={tenant_id}", headers=bearer(token))
    assert mine.status_code == 200

    theirs = client.get(
        f"/v1/dashboard/overview?tenant_id={other_tenant}", headers=bearer(token)
    )
    assert theirs.status_code == 404


@requires_stack
def test_a_viewer_cannot_configure(tenant) -> None:
    tenant_id, _ = tenant
    token = mint(tenant_id, "viewer")
    response = TestClient(app).put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "renamed", "retention_days": 30, "capture_payloads": True},
        headers=bearer(token),
    )
    assert response.status_code == 403
    assert "may not configure" in response.json()["detail"]


@requires_stack
def test_an_auditor_exports_everything_and_changes_nothing(tenant) -> None:
    """What an external assessor is handed during a compliance review."""
    tenant_id, _ = tenant
    client = TestClient(app)
    token = mint(tenant_id, "auditor")

    # Reads and exports.
    assert client.get(
        f"/v1/dashboard/overview?tenant_id={tenant_id}", headers=bearer(token)
    ).status_code == 200
    pack = client.get(
        f"/v1/compliance/pack?tenant_id={tenant_id}"
        "&period_from=2026-01-01T00:00:00Z&period_to=2027-01-01T00:00:00Z",
        headers=bearer(token),
    )
    assert pack.status_code in (200, 404, 409)  # content depends on seeded data
    assert pack.status_code != 403

    # Changes nothing.
    assert client.put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "x", "retention_days": 30, "capture_payloads": True},
        headers=bearer(token),
    ).status_code == 403
    assert client.post(
        f"/v1/settings/tokens?tenant_id={tenant_id}",
        json={"kind": "recording", "label": "sneaky"},
        headers=bearer(token),
    ).status_code == 403


@requires_stack
def test_a_responder_may_revoke_but_not_configure(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    token = mint(tenant_id, "responder")
    # Not 403: the capability is granted, so any failure is about the target.
    impact = client.get(
        f"/v1/revocation/impact?tenant_id={tenant_id}&credential_id={uuid.uuid4()}",
        headers=bearer(token),
    )
    assert impact.status_code != 403
    assert client.put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "x", "retention_days": 30, "capture_payloads": True},
        headers=bearer(token),
    ).status_code == 403


@requires_stack
def test_a_viewer_cannot_export_evidence(tenant) -> None:
    tenant_id, _ = tenant
    token = mint(tenant_id, "viewer")
    response = TestClient(app).get(
        f"/v1/evidence/tenant?tenant_id={tenant_id}", headers=bearer(token)
    )
    assert response.status_code == 403


@requires_stack
def test_a_revoked_token_stops_working(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    created = client.post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": "temp", "role": "viewer"}, headers=ADMIN,
    ).json()

    assert client.get(
        f"/v1/dashboard/overview?tenant_id={tenant_id}",
        headers=bearer(created["token"]),
    ).status_code == 200

    assert client.post(
        f"/v1/settings/read-tokens/{created['id']}/revoke?tenant_id={tenant_id}",
        headers=ADMIN,
    ).status_code == 200

    assert client.get(
        f"/v1/dashboard/overview?tenant_id={tenant_id}",
        headers=bearer(created["token"]),
    ).status_code == 401


@requires_stack
def test_an_expired_token_stops_working(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    created = client.post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": "short", "role": "viewer"}, headers=ADMIN,
    ).json()
    with pg_pool().connection() as conn:
        conn.execute(
            "UPDATE read_tokens SET expires_at = now() - INTERVAL '1 hour' WHERE id=%s",
            (created["id"],),
        )
    response = client.get(
        f"/v1/dashboard/overview?tenant_id={tenant_id}", headers=bearer(created["token"])
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


# -- the control plane is as tamper-evident as the recording plane -------------

@requires_stack
def test_admin_actions_are_chained_and_verify(tenant) -> None:
    """An attacker who cannot edit the record could otherwise still widen a
    retention policy or mint a token with nothing tamper-evident to show it."""
    from abx_api.chain import row_to_event, verify_chain
    from abx_api.store import ch_client

    tenant_id, _ = tenant
    client = TestClient(app)
    created = client.post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": "audited", "role": "auditor"}, headers=ADMIN,
    ).json()
    client.put(
        f"/v1/settings?tenant_id={tenant_id}",
        json={"tenant_name": "renamed", "retention_days": 45, "capture_payloads": True},
        headers=ADMIN,
    )

    rows = ch_client().query(
        "SELECT op_name, op_target, resource_refs FROM events "
        "WHERE tenant_id=%(t)s AND source='admin_api' ORDER BY chain_seq",
        parameters={"t": tenant_id},
    ).result_rows
    actions = {str(row[0]) for row in rows}
    assert "read token issued" in actions
    assert "settings updated" in actions
    assert any(created["id"] == str(row[1]) for row in rows)
    assert any("abx:admin-action:read token issued" in list(row[2]) for row in rows)

    chain = [row_to_event(dict(row)) for row in ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(t)s ORDER BY chain_seq",
        parameters={"t": tenant_id},
    ).named_results()]
    valid, divergent = verify_chain(chain)
    assert valid and divergent is None


# -- regressions found by the tenant-isolation audit ---------------------------

@requires_stack
def test_a_read_only_principal_cannot_rewrite_alert_delivery(tenant) -> None:
    """Found by audit. Moving the alerts router from require_admin to
    require_read wholesale left its MUTATING routes read-guarded, so an auditor
    could add an email target it controls and receive the tenant's security
    alerts - and keep receiving them after its token was revoked, because
    revoking a token does not remove an alert channel."""
    tenant_id, _ = tenant
    client = TestClient(app)
    for role in ("viewer", "auditor"):
        token = mint(tenant_id, role)
        response = client.put(
            f"/v1/alerts/channels?tenant_id={tenant_id}",
            json={"kind": "email", "target": "attacker@evil.example", "enabled": True},
            headers=bearer(token),
        )
        assert response.status_code == 403, role


@requires_stack
def test_a_read_only_principal_cannot_silence_alert_delivery(tenant) -> None:
    """The variant needing no mail provider: disabling Slack delivery blinds
    the tenant's detection while the read token still looks harmless."""
    tenant_id, _ = tenant
    response = TestClient(app).put(
        f"/v1/alerts/channels?tenant_id={tenant_id}",
        json={"kind": "slack", "target": "", "enabled": False},
        headers=bearer(mint(tenant_id, "auditor")),
    )
    assert response.status_code == 403


@requires_stack
def test_a_read_only_principal_cannot_clear_alerts(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    assert client.post(
        f"/v1/alerts/{uuid.uuid4()}/acknowledge?tenant_id={tenant_id}",
        headers=bearer(mint(tenant_id, "viewer")),
    ).status_code == 403
    # A responder triages; that is the whole role.
    assert client.post(
        f"/v1/alerts/{uuid.uuid4()}/acknowledge?tenant_id={tenant_id}",
        headers=bearer(mint(tenant_id, "responder")),
    ).status_code != 403


@requires_stack
def test_a_read_only_principal_cannot_trigger_evaluation(tenant) -> None:
    tenant_id, _ = tenant
    assert TestClient(app).post(
        f"/v1/alerts/evaluate?tenant_id={tenant_id}",
        headers=bearer(mint(tenant_id, "viewer")),
    ).status_code == 403


@requires_stack
def test_a_project_connected_elsewhere_cannot_be_claimed(tenant, monkeypatch) -> None:
    """Found by audit. The GCP scanner uses ONE deployment-wide principal, so a
    tenant that names another tenant's project would receive that tenant's
    findings. Project ids are guessable."""
    from abx_api import integrations

    tenant_id, _ = tenant
    # Settings is a frozen dataclass, so replace the module's reference.
    monkeypatch.setattr(
        integrations, "settings",
        replace(integrations.settings, gcp_scanner_principal="scanner@example.iam"),
    )
    monkeypatch.setattr(integrations, "enqueue_gcp_scan", lambda *a, **k: None)

    with pg_pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"victim-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
    victim = str(row[0])
    project = f"victim-project-{uuid.uuid4().hex[:8]}"

    client = TestClient(app)
    first = client.post(
        f"/v1/integrations/gcp/connect?tenant_id={victim}",
        json={"project_id": project}, headers=ADMIN,
    )
    assert first.status_code == 200, first.text

    stolen = client.post(
        f"/v1/integrations/gcp/connect?tenant_id={tenant_id}",
        json={"project_id": project}, headers=ADMIN,
    )
    assert stolen.status_code == 409
    assert "another workspace" in stolen.json()["detail"]

    # Nothing was written and no scan was queued for the claiming tenant.
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT tenant_id FROM integration_connections "
            "WHERE provider='gcp' AND external_id=%s",
            (project,),
        ).fetchall()
    assert [str(r[0]) for r in rows] == [victim]


@requires_stack
def test_reconnecting_your_own_project_still_works(tenant, monkeypatch) -> None:
    from abx_api import integrations

    tenant_id, _ = tenant
    # Settings is a frozen dataclass, so replace the module's reference.
    monkeypatch.setattr(
        integrations, "settings",
        replace(integrations.settings, gcp_scanner_principal="scanner@example.iam"),
    )
    monkeypatch.setattr(integrations, "enqueue_gcp_scan", lambda *a, **k: None)
    project = f"own-project-{uuid.uuid4().hex[:8]}"
    client = TestClient(app)
    for _ in range(2):
        response = client.post(
            f"/v1/integrations/gcp/connect?tenant_id={tenant_id}",
            json={"project_id": project}, headers=ADMIN,
        )
        assert response.status_code == 200, response.text
