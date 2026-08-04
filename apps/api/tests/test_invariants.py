"""Product invariants under a dishonest agent (plansecurity SP-6).

The gate's exit criterion is specific and unusual: *every invariant has one
negative test that would fail if the protection were removed*. That rules out
the most common shape of invariant test, which asserts the happy path and would
pass just as well with the protection deleted.

So each test here does two things: shows the protection holding, and shows what
the same input produces with the protection bypassed. If those two are ever the
same value, the test is measuring nothing.

Scope note on the storage sweep below. Payload bodies are envelope-encrypted at
rest, so grepping object storage for a plaintext secret finds nothing whether
redaction ran or not - the ciphertext hides the answer either way. A sweep that
cannot distinguish success from failure is not evidence, so the storage
assertions target the layers that hold cleartext: ClickHouse columns, Postgres
rows, and everything the API hands back.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from abx_api.anchor import anchor_all
from abx_api.ingest import _scrub_credential_ref, ingest_events
from abx_api.main import app
from abx_api.reports import _md
from abx_api.settings import settings
from abx_api.store import ch_client
from abx_schemas import IngestEvent
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient
from psycopg import sql

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}

#: Synthetic, structurally valid, never issued by any provider.
#:
#: The distinction between these two is the whole point of this file. An AWS
#: access key ID is the PUBLIC half of the pair - the scanner stores it verbatim
#: as credentials.fingerprint and the replay timeline joins on it - so scrubbing
#: it from a credential reference would break a feature and protect nothing.
#: A GitHub token is the secret itself and must never be stored.
AWS_KEY_ID = "AKIA" + "Q" * 16
GITHUB_PAT = "ghp_" + "b" * 36


@pytest.fixture
def sweep_tenant():
    from abx_api.auth import new_ingest_token
    from abx_api.store import ensure_buckets

    ensure_buckets()
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"inv-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        assert row is not None
        tenant_id = str(row[0])
        token, token_hash = new_ingest_token()
        conn.execute(
            "INSERT INTO ingest_tokens (tenant_id, token_hash, label) VALUES (%s,%s,'inv')",
            (tenant_id, token_hash),
        )
    try:
        yield tenant_id, token
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
            _delete_tenant_data(conn, tenant_id)
            conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))


def event(session_id: str, seq: int, *, credential_ref: str, payload: str | None):
    return IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "invariant-agent",
        "session_id": session_id, "seq": seq, "ts": "2026-08-01T00:00:00.000Z",
        "source": "mcp_tap", "event_type": "tool_call",
        "operation": {
            "name": "call", "provider": "aws", "target": "t",
            "outcome": "success", "duration_ms": 1,
        },
        "credential_ref": credential_ref, "resource_refs": ["aws:s3:x"], "payload": payload,
    })


# -- the graph holds fingerprints, never secret values --------------------------

@requires_stack
def test_a_secret_in_credential_ref_never_reaches_storage(sweep_tenant) -> None:
    """credential_ref is agent-supplied, and the schema's word for it is not a control.

    The field is documented as "a fingerprint reference into the identity graph;
    never a secret value". An agent that puts a real key there - maliciously, or
    by passing the wrong variable - must not have it persisted, because the
    recording plane does not depend on the agent's honesty.

    The second event deliberately carries no payload: that path returns early
    from preparation, and an early return is exactly where a scrub gets skipped.
    """
    tenant_id, _ = sweep_tenant
    session_id = f"inv-{uuid.uuid4().hex[:8]}"
    ingest_events(tenant_id, [
        event(session_id, 0, credential_ref=GITHUB_PAT, payload="body"),
        event(session_id, 1, credential_ref=GITHUB_PAT, payload=None),
    ])

    stored = ch_client().query(
        "SELECT seq, credential_ref, redactions FROM events "
        "WHERE tenant_id = %(t)s ORDER BY seq",
        parameters={"t": tenant_id},
    ).result_rows
    assert len(stored) == 2
    for seq, credential_ref, redactions in stored:
        assert GITHUB_PAT not in credential_ref, f"seq {seq} stored the raw token"
        assert credential_ref.startswith("[REDACTED:github-token:"), (seq, credential_ref)
        assert "github-token" in redactions, f"seq {seq} did not record the redaction"

    # Every surface must be searched while it is actually serving. "the token is
    # absent" is true of a 409 body too, so each response is pinned to 200 and to
    # a marker proving it rendered this session before the absence is believed.
    anchor_all()
    client = TestClient(app)
    for path, marker in (
        (f"/v1/replay/sessions/{session_id}", session_id),
        (f"/v1/reports/sessions/{session_id}.md", _md(session_id)),
        ("/v1/evidence/tenant", session_id),
    ):
        response = client.get(path, params={"tenant_id": tenant_id}, headers=ADMIN)
        assert response.status_code == 200, (path, response.status_code, response.text[:200])
        assert marker in response.text, f"{path} returned nothing about this session"
        assert GITHUB_PAT not in response.text, f"{path} echoed the raw token"


def test_the_scrub_would_be_visible_if_it_were_removed() -> None:
    """The negative control the gate asks for.

    Compare the value the pipeline stores against the value the agent sent. If
    those were ever equal for a secret-bearing ref, every assertion above would
    pass with the protection deleted.
    """
    hostile = event("s", 0, credential_ref=GITHUB_PAT, payload=None)
    scrubbed, fired = _scrub_credential_ref(hostile)

    assert hostile.credential_ref == GITHUB_PAT, "the input itself must carry the secret"
    assert scrubbed.credential_ref != hostile.credential_ref, "removing the scrub is undetectable"
    assert fired == ["github-token"]

    # An access key ID passes through untouched. This is not leniency: it is the
    # value credentials.fingerprint holds, and the replay timeline joins events
    # to credentials on it. Scrubbing it would break that join while protecting
    # nothing, because the id is the public half of the pair.
    for fingerprint in (AWS_KEY_ID, "AKIA-DEMO-POCKETOS"):
        untouched, none_fired = _scrub_credential_ref(
            event("s", 0, credential_ref=fingerprint, payload=None)
        )
        assert untouched.credential_ref == fingerprint
        assert none_fired == []


@requires_stack
def test_the_chain_commits_to_the_scrubbed_value(sweep_tenant) -> None:
    """The canonical event must be hashed over the value that is actually stored.

    Honest about what this does and does not catch. Deleting the scrub entirely
    leaves this test green, because the chain hashes whatever it stores and both
    would simply be the raw key - the three tests above are what detect that.
    What this one detects is the scrub running in the wrong place: applied after
    the event is hashed, the database and an exported bundle would disagree and
    offline verification of that bundle would fail.
    """
    tenant_id, _ = sweep_tenant
    session_id = f"inv-{uuid.uuid4().hex[:8]}"
    ingest_events(tenant_id, [event(session_id, 0, credential_ref=GITHUB_PAT, payload=None)])
    result = TestClient(app).get(
        "/v1/chain/verify", params={"tenant_id": tenant_id}, headers=ADMIN
    ).json()
    assert result["valid"] is True, result


# -- cleartext storage sweep ---------------------------------------------------

@requires_stack
def test_no_cleartext_secret_survives_in_any_readable_store(sweep_tenant) -> None:
    """Postgres, ClickHouse, and every API surface, for a payload full of secrets.

    Object storage is deliberately excluded: payload bodies are encrypted at
    rest, so a plaintext search there returns nothing whether redaction ran or
    not, and a check that cannot fail is not a check.

    The same reasoning applies to a non-200: an error body contains no secret
    either. Each API surface is pinned to 200 and to a marker showing it
    rendered THIS session, so absence is evidence rather than an artifact of the
    request having failed. Evidence export needs an anchor before it will serve
    at all, which is exactly how this was passing without searching anything.
    """
    tenant_id, _ = sweep_tenant
    session_id = f"inv-{uuid.uuid4().hex[:8]}"
    ingest_events(tenant_id, [
        event(
            session_id, 0, credential_ref=AWS_KEY_ID,
            payload=f"{AWS_KEY_ID} and {GITHUB_PAT}",
        ),
    ])

    events = str(ch_client().query(
        "SELECT * FROM events WHERE tenant_id = %(t)s", parameters={"t": tenant_id}
    ).result_rows)
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        tables = [
            name for (name,) in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
            ).fetchall()
        ]
        rows = []
        for table in tables:
            # Identifier() rather than an f-string: these names come from
            # information_schema, so they are not hostile, but a table whose
            # name contains a quote would silently break the sweep and take a
            # storage layer out of scope without failing anything.
            rows.append(str(conn.execute(
                sql.SQL("SELECT * FROM {}").format(sql.Identifier(table))
            ).fetchall()))
    postgres = " ".join(rows)

    anchor_all()
    client = TestClient(app)
    surfaces = {"clickhouse": events, "postgres": postgres}
    for name, path, marker in (
        ("replay", f"/v1/replay/sessions/{session_id}", session_id),
        ("report", f"/v1/reports/sessions/{session_id}.md", _md(session_id)),
        ("evidence", "/v1/evidence/tenant", session_id),
    ):
        response = client.get(path, params={"tenant_id": tenant_id}, headers=ADMIN)
        assert response.status_code == 200, (name, response.status_code, response.text[:200])
        assert marker in response.text, f"{name} returned nothing about this session"
        surfaces[name] = response.text

    for name, body in surfaces.items():
        # The token must be gone from every layer. The access key ID survives in
        # credential_ref by design, so it is asserted absent from the payload
        # rather than from the whole surface.
        assert GITHUB_PAT not in body, f"{name} holds a cleartext token"
    replay_payload = " ".join(
        str(item.get("payload"))
        for item in TestClient(app).get(
            f"/v1/replay/sessions/{session_id}", params={"tenant_id": tenant_id}, headers=ADMIN
        ).json()["timeline"]
        if item.get("kind") == "event"
    )
    assert AWS_KEY_ID not in replay_payload, "the payload was not redacted"

    # And the sweep is not passing because nothing was recorded at all. The
    # payload itself lives in object storage, so ClickHouse is checked for the
    # redactions column rather than for a marker: that column is the record of
    # which rules fired, and an empty one means redaction never ran.
    fired = ch_client().query(
        "SELECT redactions FROM events WHERE tenant_id = %(t)s", parameters={"t": tenant_id}
    ).result_rows
    assert fired and fired[0][0], "no event reached ClickHouse, or redaction never ran"
    assert "github-token" in fired[0][0], fired[0][0]
