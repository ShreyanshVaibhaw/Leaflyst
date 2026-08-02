"""Runtime policy plane: management, advisory mode, and decision recording.

Enforcement is OFF unless a tenant turns it on. The product's failure mode is
"agent keeps working, recording degrades", and a blocking plane inverts that -
so it cannot be something a customer discovers they had. Until they opt in,
policies are evaluated and recorded but nothing is blocked, which lets them see
what a policy WOULD have done before it can hurt them.
"""

from __future__ import annotations

from abx_api.main import app
from abx_api.store import ch_client, pg_pool
from conftest import requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-Abx-Admin-Key": "dev-admin-key"}

DESTRUCTIVE_POLICY = {
    "policy_id": "no-destructive",
    "effect": "deny",
    "description": "destructive operations are blocked",
    "match_destructive": True,
}


def put_policy(tenant_id: str, body: dict) -> dict:
    response = TestClient(app).put(
        f"/v1/policy?tenant_id={tenant_id}", json=body, headers=ADMIN
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def enforce(tenant_id: str, enabled: bool) -> None:
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "policy_enforcement) VALUES (%s,30,TRUE,%s) ON CONFLICT (tenant_id) "
            "DO UPDATE SET policy_enforcement=EXCLUDED.policy_enforcement",
            (tenant_id, enabled),
        )


def ask(tenant_id: str, **body: object) -> dict:
    response = TestClient(app).post(
        f"/v1/policy/decide?tenant_id={tenant_id}",
        json={"agent_id": "bot", **body}, headers=ADMIN,
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


# -- opt-in ---------------------------------------------------------------------

@requires_stack
def test_enforcement_is_off_by_default(tenant) -> None:
    """A blocking plane must never be something a customer discovers they had."""
    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    decision = ask(tenant_id, operation="files/delete")
    assert decision["enforcement_enabled"] is False
    assert decision["allowed"] is True
    assert "enforcement is disabled" in decision["reason"]
    # It still says what it WOULD have done.
    assert "would have been deny" in decision["reason"]


@requires_stack
def test_opting_in_makes_the_same_policy_block(tenant) -> None:
    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    enforce(tenant_id, True)
    decision = ask(tenant_id, operation="files/delete")
    assert decision["enforcement_enabled"] is True
    assert decision["allowed"] is False
    assert decision["policy_id"] == "no-destructive"


@requires_stack
def test_an_unmatched_action_is_allowed_under_enforcement(tenant) -> None:
    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    enforce(tenant_id, True)
    assert ask(tenant_id, operation="tools/list")["allowed"] is True


# -- versioning -----------------------------------------------------------------

@requires_stack
def test_editing_a_policy_writes_a_new_version_and_keeps_the_old(tenant) -> None:
    """A customer must be able to prove which policy was in force at any past
    moment, so history is retained the way the event log retains events."""
    tenant_id, _ = tenant
    first = put_policy(tenant_id, DESTRUCTIVE_POLICY)
    assert first["version"] == 1
    second = put_policy(tenant_id, {**DESTRUCTIVE_POLICY, "description": "tightened"})
    assert second["version"] == 2

    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT version, superseded_at FROM policies WHERE tenant_id=%s "
            "AND policy_id='no-destructive' ORDER BY version",
            (tenant_id,),
        ).fetchall()
    assert [int(row[0]) for row in rows] == [1, 2]
    assert rows[0][1] is not None  # v1 superseded, not deleted
    assert rows[1][1] is None

    # Only the live version is listed and enforced.
    listed = TestClient(app).get(
        f"/v1/policy?tenant_id={tenant_id}", headers=ADMIN
    ).json()
    assert [item["version"] for item in listed] == [2]


@requires_stack
def test_the_decision_reports_the_version_that_matched(tenant) -> None:
    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    put_policy(tenant_id, {**DESTRUCTIVE_POLICY, "description": "v2"})
    enforce(tenant_id, True)
    assert ask(tenant_id, operation="files/delete")["policy_version"] == 2


# -- guardrails ------------------------------------------------------------------

@requires_stack
def test_a_policy_with_no_conditions_is_refused(tenant) -> None:
    """A half-written deny would otherwise become a deny-everything."""
    tenant_id, _ = tenant
    response = TestClient(app).put(
        f"/v1/policy?tenant_id={tenant_id}",
        json={"policy_id": "empty", "effect": "deny"}, headers=ADMIN,
    )
    assert response.status_code == 422
    assert "at least one match condition" in response.json()["detail"]


@requires_stack
def test_a_malformed_policy_id_is_refused(tenant) -> None:
    tenant_id, _ = tenant
    response = TestClient(app).put(
        f"/v1/policy?tenant_id={tenant_id}",
        json={"policy_id": "Not Valid!", "effect": "deny", "match_destructive": True},
        headers=ADMIN,
    )
    assert response.status_code == 422


@requires_stack
def test_only_an_admin_may_write_policy(tenant) -> None:
    """A read-only principal that could edit policy could disable the blocking
    it is subject to."""
    tenant_id, _ = tenant
    client = TestClient(app)
    viewer = client.post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": "v", "role": "viewer"}, headers=ADMIN,
    ).json()["token"]
    assert client.put(
        f"/v1/policy?tenant_id={tenant_id}", json=DESTRUCTIVE_POLICY,
        headers={"Authorization": f"Bearer {viewer}"},
    ).status_code == 403
    # Reading policy is fine.
    assert client.get(
        f"/v1/policy?tenant_id={tenant_id}",
        headers={"Authorization": f"Bearer {viewer}"},
    ).status_code == 200


# -- every decision is on the record ---------------------------------------------

@requires_stack
def test_both_allows_and_denies_are_chained(tenant) -> None:
    """A deny that leaves no trace is indistinguishable from an agent bug, and
    an allow that leaves no trace makes it impossible to tell 'considered and
    permitted' from 'never evaluated'."""
    from abx_api.chain import row_to_event, verify_chain

    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    enforce(tenant_id, True)
    ask(tenant_id, operation="files/delete")
    ask(tenant_id, operation="tools/list")

    rows = ch_client().query(
        "SELECT op_name, op_outcome, resource_refs FROM events "
        "WHERE tenant_id=%(t)s AND startsWith(op_name,'policy decision') "
        "ORDER BY chain_seq",
        parameters={"t": tenant_id},
    ).result_rows
    outcomes = [str(row[1]) for row in rows]
    assert "denied" in outcomes
    assert "success" in outcomes
    refs = [ref for row in rows for ref in row[2]]
    assert "abx:policy-decision:deny" in refs
    assert "abx:policy:no-destructive:v1" in refs

    chain = [row_to_event(dict(row)) for row in ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(t)s ORDER BY chain_seq",
        parameters={"t": tenant_id},
    ).named_results()]
    valid, divergent = verify_chain(chain)
    assert valid and divergent is None


@requires_stack
def test_an_advisory_decision_is_marked_as_advisory(tenant) -> None:
    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    enforce(tenant_id, False)
    ask(tenant_id, operation="files/delete")

    refs = [
        ref for row in ch_client().query(
            "SELECT resource_refs FROM events WHERE tenant_id=%(t)s "
            "AND startsWith(op_name,'policy decision')",
            parameters={"t": tenant_id},
        ).result_rows for ref in row[0]
    ]
    assert "abx:policy-advisory:true" in refs


@requires_stack
def test_policy_edits_are_chained(tenant) -> None:
    tenant_id, _ = tenant
    put_policy(tenant_id, DESTRUCTIVE_POLICY)
    rows = ch_client().query(
        "SELECT op_target FROM events WHERE tenant_id=%(t)s "
        "AND op_name='policy updated'",
        parameters={"t": tenant_id},
    ).result_rows
    assert [str(row[0]) for row in rows] == ["no-destructive"]


@requires_stack
def test_a_decision_never_returns_an_error_status(tenant, monkeypatch) -> None:
    """A plane that raises into the agent's path is how enforcement takes down
    an agent. A failure is a decision, not a 500."""
    import abx_api.policy as policy_module

    tenant_id, _ = tenant

    def broken(*_args: object, **_kwargs: object):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(policy_module, "pg_pool", broken)
    response = TestClient(app).post(
        f"/v1/policy/decide?tenant_id={tenant_id}",
        json={"agent_id": "bot", "operation": "files/delete"}, headers=ADMIN,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is True
    assert body["degraded"] is True
