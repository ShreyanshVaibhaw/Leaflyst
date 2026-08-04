"""Surface added after the August 1 audit (plansecurity SP-6b).

The audit predates the runtime policy plane, the streamable HTTP tap, scoped
read tokens, payload tiering, and control-plane chaining. No earlier gate names
any of it, and a gate list that quietly omits new attack surface reads as
coverage rather than as a gap.

The same rule as SP-6 applies to everything here: a check that would pass with
the protection deleted is not a check, so each test either compares against the
unprotected behaviour or is labelled with what it does not catch.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client, pg_pool

# Imported at module scope on purpose. Deferred inside a function body, a
# workspace-wide run resolves `conftest` to services/scanner/tests/conftest.py
# and the import fails there but not when this file runs alone.
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-Abx-Admin-Key": "dev-admin-key"}


def producer_event(session_id: str, seq: int, source: str) -> dict:
    """A batch entry as a producer would put it on the wire."""
    return {
        "event_id": str(uuid.uuid4()), "agent_id": "hostile-agent",
        "session_id": session_id, "seq": seq, "ts": "2026-08-01T00:00:00.000Z",
        "source": source, "event_type": "agent_step",
        "operation": {
            "name": "credential revoked by operator", "provider": "leaflyst",
            "target": "prod-admin-key", "outcome": "success", "duration_ms": 0,
        },
        "resource_refs": ["aws:iam:prod-admin"], "payload": None,
    }


def submit(token: str, events: list[dict]):
    return TestClient(app).post(
        "/v1/ingest", json={"events": events},
        headers={"Authorization": f"Bearer {token}"},
    )


# -- a producer cannot forge a control-plane event ------------------------------

@requires_stack
def test_a_producer_cannot_claim_the_control_plane_source(tenant) -> None:
    """`admin_api` marks an event as the operator's own action.

    Two things downstream trust that mark: an auditor reads such a record as
    "an operator did this", and metering skips it so our own bookkeeping cannot
    eat a tenant's plan allowance. Both are safe only while the mark is ours to
    apply, and a write-only ingest token is not the control plane.
    """
    tenant_id, token = tenant
    session_id = f"forge-{uuid.uuid4().hex[:8]}"

    rejected = submit(token, [producer_event(session_id, 0, "admin_api")])
    assert rejected.status_code == 422, rejected.text
    assert "reserved for the control plane" in rejected.text

    stored = ch_client().query(
        "SELECT count() FROM events WHERE tenant_id=%(t)s AND source='admin_api'",
        parameters={"t": tenant_id},
    ).result_rows
    assert int(stored[0][0]) == 0, "a forged operator action reached the chain"


@requires_stack
def test_one_forged_event_rejects_the_whole_batch(tenant) -> None:
    """Rejected as a batch, not filtered.

    Dropping the offending event and accepting the rest would leave the producer
    with a working channel and no signal, and would renumber nothing while
    silently changing what the caller believes it recorded.
    """
    tenant_id, token = tenant
    session_id = f"forge-{uuid.uuid4().hex[:8]}"

    response = submit(token, [
        producer_event(session_id, 0, "mcp_tap"),
        producer_event(session_id, 1, "admin_api"),
    ])
    assert response.status_code == 422, response.text

    stored = ch_client().query(
        "SELECT count() FROM events WHERE tenant_id=%(t)s", parameters={"t": tenant_id},
    ).result_rows
    assert int(stored[0][0]) == 0, "the honest half of a forged batch was accepted"


@requires_stack
def test_the_forgery_would_be_an_unmetered_channel(tenant) -> None:
    """The negative control, and the reason this is not only an audit concern.

    Metering deliberately skips `admin_api`. With the source producer-settable
    that exclusion IS the exploit: every event labelled `admin_api` is ingested
    for free, straight past the tenant's plan limit. This shows an honest batch
    of the same size being counted, so the exclusion above cannot be reached.
    """
    tenant_id, token = tenant
    session_id = f"meter-{uuid.uuid4().hex[:8]}"

    accepted = submit(token, [
        producer_event(session_id, 0, "mcp_tap"),
        producer_event(session_id, 1, "mcp_tap"),
    ])
    assert accepted.status_code == 200, accepted.text

    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT events FROM metering_daily WHERE tenant_id=%s AND day=CURRENT_DATE",
            (tenant_id,),
        ).fetchone()
    assert row is not None and int(row[0]) == 2, (
        f"two accepted events metered as {row}; if a producer could label them "
        f"admin_api this count would be 0"
    )


@requires_stack
def test_the_control_plane_itself_still_records(tenant) -> None:
    """The guard is at the HTTP boundary, so in-process callers are unaffected.

    Without this, the check above could be satisfied by breaking control-plane
    recording altogether, which is the opposite of what SP-6b asks for.
    """
    from abx_api.admin_audit import record_admin_action

    tenant_id, _token = tenant
    assert record_admin_action(tenant_id, "retention changed", "30d") is True

    stored = ch_client().query(
        "SELECT count() FROM events WHERE tenant_id=%(t)s AND source='admin_api'",
        parameters={"t": tenant_id},
    ).result_rows
    assert int(stored[0][0]) == 1


# -- policy failure never degrades recording, and never inverts -----------------

def enforce(tenant_id: str, enabled: bool) -> None:
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "policy_enforcement) VALUES (%s,30,TRUE,%s) ON CONFLICT (tenant_id) "
            "DO UPDATE SET policy_enforcement=EXCLUDED.policy_enforcement",
            (tenant_id, enabled),
        )


def put_policy(tenant_id: str, body: dict) -> None:
    response = TestClient(app).put(
        f"/v1/policy?tenant_id={tenant_id}", json=body, headers=ADMIN
    )
    assert response.status_code == 200, response.text


def ask(token: str) -> dict:
    response = TestClient(app).post(
        "/v1/policy/decide",
        json={"agent_id": "bot", "operation": "files/delete"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


FAIL_CLOSED = {
    "policy_id": "must-not-guess", "effect": "deny", "on_error": "deny",
    "description": "deny when evaluation is impossible", "match_destructive": True,
}


@pytest.fixture
def broken_policy_store(monkeypatch):
    """Kill only the policy module's pool; token auth resolves elsewhere."""
    import abx_api.policy as policy_module

    def down(*_args: object, **_kwargs: object):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(policy_module, "pg_pool", down)
    return policy_module


@requires_stack
def test_a_fail_closed_tenant_is_still_denied_when_the_store_dies(
    tenant, monkeypatch
) -> None:
    """The opt-in must survive the failure it exists for.

    `on_evaluation_failure` picks fail-closed policies out of the list it is
    handed, and that list comes from the policy store. So in the one situation
    the opt-in was chosen for - the store being unreachable - the list was empty
    and the tenant who asked to be denied was allowed. The opt-in lived inside
    the thing that died.
    """
    tenant_id, token = tenant
    enforce(tenant_id, True)
    put_policy(tenant_id, FAIL_CLOSED)

    healthy = ask(token)
    assert healthy["allowed"] is False, healthy

    import abx_api.policy as policy_module

    def down(*_args: object, **_kwargs: object):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(policy_module, "pg_pool", down)
    degraded = ask(token)
    assert degraded["degraded"] is True, degraded
    assert degraded["allowed"] is False, (
        "the tenant opted into fail-closed and was allowed when the store died"
    )
    assert degraded["policy_id"] == "must-not-guess"


@requires_stack
def test_a_tenant_that_never_opted_in_is_allowed_when_the_store_dies(
    tenant, broken_policy_store
) -> None:
    """The negative control for the test above, and the product's default.

    Fail-open is what a tenant gets unless they asked otherwise: the recording
    plane degrades, the agent keeps working. If this ever denied, the fix above
    would have turned a store outage into an outage of every customer's agent.
    """
    _tenant_id, token = tenant
    decision = ask(token)
    assert decision["allowed"] is True, decision
    assert decision["degraded"] is True


@requires_stack
def test_turning_a_policy_off_cannot_make_the_system_stricter(
    tenant, monkeypatch
) -> None:
    """Disabling a policy must disable its failure behaviour with it.

    A remembered opt-in that outlives the policy would mean an operator who
    turns enforcement off makes the next outage BLOCK, which is precisely
    backwards.
    """
    tenant_id, token = tenant
    enforce(tenant_id, True)
    put_policy(tenant_id, FAIL_CLOSED)
    assert ask(token)["allowed"] is False

    put_policy(tenant_id, {**FAIL_CLOSED, "enabled": False})

    import abx_api.policy as policy_module

    def down(*_args: object, **_kwargs: object):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(policy_module, "pg_pool", down)
    decision = ask(token)
    assert decision["allowed"] is True, (
        "a disabled policy kept denying from cache after the store died"
    )


@requires_stack
def test_an_evaluation_that_raises_returns_a_decision_not_a_500(
    tenant, monkeypatch
) -> None:
    """A plane in the agent's request path must never raise into it.

    The guard used to cover only the database load, leaving evaluation itself
    outside it: anything `decide` raised became a 500 in the agent's path, which
    is the failure mode this product exists to avoid.
    """
    import abx_api.policy as policy_module

    _tenant_id, token = tenant

    def explode(*_args: object, **_kwargs: object):
        raise RuntimeError("evaluation bug")

    monkeypatch.setattr(policy_module, "decide", explode)
    response = TestClient(app).post(
        "/v1/policy/decide",
        json={"agent_id": "bot", "operation": "files/delete"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["allowed"] is True
    assert body["degraded"] is True


@requires_stack
def test_a_dead_policy_store_does_not_stop_ingest_from_chaining(
    tenant, broken_policy_store
) -> None:
    """Enforcement is a new deny path in a product whose failure mode is
    "the agent keeps working, recording degrades". Recording must not acquire a
    dependency on it.
    """
    tenant_id, token = tenant
    session_id = f"policy-down-{uuid.uuid4().hex[:8]}"

    accepted = submit(token, [producer_event(session_id, 0, "mcp_tap")])
    assert accepted.status_code == 200, accepted.text

    verified = TestClient(app).get(
        "/v1/chain/verify", params={"tenant_id": tenant_id}, headers=ADMIN
    ).json()
    assert verified["valid"] is True, verified


@requires_stack
def test_a_tenant_cannot_enable_enforcement_for_another_tenant(tenant) -> None:
    """Policy writes are tenant-scoped like every other query."""
    tenant_id, _token = tenant
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"victim-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        other = str(row[0])
    try:
        put_policy(tenant_id, FAIL_CLOSED)
        with pg_pool().connection() as conn:
            leaked = conn.execute(
                "SELECT count(*) FROM policies WHERE tenant_id=%s", (other,)
            ).fetchone()
        assert int(leaked[0]) == 0
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
            _delete_tenant_data(conn, other)
            conn.execute("DELETE FROM tenants WHERE id=%s", (other,))
