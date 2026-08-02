"""EU AI Act Article 12 evidence pack.

The pack is only worth something if an auditor holding nothing but the exported
chain and the single-file verifier reaches the same conclusion the product
does. These tests drive the real endpoints and then verify the export with the
actual `abx_verify.py`, not a reimplementation of it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path

from abx_api.anchor import anchor_all
from abx_api.compliance import UNATTRIBUTED_REASON
from abx_api.ingest import ingest_events
from abx_api.main import app
from abx_api.store import ch_client, pg_pool
from abx_schemas import IngestEvent
from conftest import requires_stack
from fastapi.testclient import TestClient

VERIFY_PATH = Path(__file__).parents[3] / "tools" / "abx_verify.py"
SPEC = importlib.util.spec_from_file_location("abx_standalone_verify_pack", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

ADMIN = {"X-Abx-Admin-Key": "dev-admin-key"}
PERIOD = {"period_from": "2026-01-01T00:00:00Z", "period_to": "2027-01-01T00:00:00Z"}


def an_event(session_id: str, ts: str = "2026-07-30T12:00:00.000Z") -> IngestEvent:
    return IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "agent-a", "session_id": session_id,
        "seq": 0, "ts": ts, "source": "mcp_tap", "event_type": "mcp_request",
        "operation": {"name": "tools/call echo", "outcome": "success"},
        "resource_refs": [],
    })


def seeded_tenant(tenant_id: str) -> None:
    ingest_events(tenant_id, [an_event(f"s-{uuid.uuid4()}")], operator_ref="operator-alice")
    ingest_events(tenant_id, [an_event(f"s-{uuid.uuid4()}")])
    anchor_all()


def fetch_pack(client: TestClient, tenant_id: str) -> dict:
    response = client.get(
        f"/v1/compliance/pack?tenant_id={tenant_id}"
        f"&period_from={PERIOD['period_from']}&period_to={PERIOD['period_to']}",
        headers=ADMIN,
    )
    assert response.status_code == 200, response.text
    return response.json()


@requires_stack
def test_pack_reports_attributed_and_unattributed_activity(tenant) -> None:
    """Article 12(3) asks who was involved. Activity with no operator must be
    reported as explicitly unattributed with a reason, never omitted and never
    ascribed to whoever happens to be handy."""
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    pack = fetch_pack(TestClient(app), tenant_id)

    roster = {entry["operator_ref"]: entry for entry in pack["operator_roster"]}
    assert "operator-alice" in roster
    assert roster["operator-alice"]["unattributed_reason"] is None
    assert None in roster
    assert roster[None]["unattributed_reason"] == UNATTRIBUTED_REASON

    assert pack["chain"]["attributed_events"] >= 1
    assert pack["chain"]["unattributed_events"] >= 1
    assert pack["chain"]["period_events"] == (
        pack["chain"]["attributed_events"] + pack["chain"]["unattributed_events"]
    )


@requires_stack
def test_pack_states_the_retention_policy_in_force(tenant) -> None:
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads,"
            "compliance_mode,retention_floor_days) VALUES (%s,365,TRUE,TRUE,180) "
            "ON CONFLICT (tenant_id) DO UPDATE SET retention_days=365,"
            "compliance_mode=TRUE,retention_floor_days=180,updated_at=now()",
            (tenant_id,),
        )
    policy = fetch_pack(TestClient(app), tenant_id)["retention_policy"]
    assert policy["retention_days"] == 365
    assert policy["compliance_mode"] is True
    assert policy["meets_article_12_minimum"] is True
    assert policy["article_12_minimum_days"] == 180
    assert policy["policy_version"] != "default"


@requires_stack
def test_pack_flags_retention_below_the_article_12_minimum(tenant) -> None:
    """A tenant not in compliance mode may retain for 30 days. The pack must
    say so plainly rather than implying the record satisfies Article 12."""
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO tenant_settings (tenant_id,retention_days,capture_payloads) "
            "VALUES (%s,30,TRUE) ON CONFLICT (tenant_id) DO UPDATE SET retention_days=30",
            (tenant_id,),
        )
    policy = fetch_pack(TestClient(app), tenant_id)["retention_policy"]
    assert policy["meets_article_12_minimum"] is False


@requires_stack
def test_exported_chain_verifies_offline_with_the_real_verifier(tenant, tmp_path) -> None:
    """The whole pack rests on this: an auditor with only the NDJSON and the
    single-file script reaches the same verdict."""
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    client = TestClient(app)
    pack = fetch_pack(client, tenant_id)

    export = client.get(f"/v1/evidence/tenant?tenant_id={tenant_id}", headers=ADMIN)
    assert export.status_code == 200
    bundle = tmp_path / "chain.ndjson"
    bundle.write_bytes(export.content)

    result = VERIFIER.verify_file(bundle, pack["verification"]["anchor_hash"])
    assert result.valid, result.message
    assert result.events_checked == pack["chain"]["exported_through_seq"]


@requires_stack
def test_tampering_with_an_exported_event_fails_verification(tenant, tmp_path) -> None:
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    client = TestClient(app)
    pack = fetch_pack(client, tenant_id)
    export = client.get(f"/v1/evidence/tenant?tenant_id={tenant_id}", headers=ADMIN)

    lines = export.content.decode().strip().split("\n")
    forged = []
    for line in lines:
        record = json.loads(line)
        if record.get("type") == "event" and record["chain_seq"] == 1:
            record["event"]["operator_ref"] = "someone-else"
        forged.append(json.dumps(record, separators=(",", ":")))
    bundle = tmp_path / "forged.ndjson"
    bundle.write_text("\n".join(forged) + "\n", encoding="utf-8")

    result = VERIFIER.verify_file(bundle, pack["verification"]["anchor_hash"])
    assert not result.valid
    assert result.first_divergent_event_id is not None


@requires_stack
def test_generating_a_pack_is_itself_chained(tenant) -> None:
    """Otherwise the manifest is an unsigned claim a vendor made about itself:
    the attestation is what makes a past pack's assertions tamper-evident."""
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    pack = fetch_pack(TestClient(app), tenant_id)

    rows = ch_client().query(
        "SELECT resource_refs FROM events WHERE tenant_id=%(t)s "
        "AND op_name='compliance evidence pack generated'",
        parameters={"t": tenant_id},
    ).result_rows
    assert rows, "pack generation should be recorded in the tenant chain"
    refs = [ref for row in rows for ref in row[0]]
    assert f"abx:compliance-pack:{pack['manifest_digest']}" in refs


@requires_stack
def test_pack_maps_every_clause_to_a_checkable_artifact(tenant) -> None:
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    pack = fetch_pack(TestClient(app), tenant_id)

    mapping = pack["article_12_mapping"]
    assert mapping
    for entry in mapping:
        assert entry["clause"] and entry["requirement"]
        assert entry["artifact"] and entry["how_to_check"]
    assert any("Article 12(3)" in entry["clause"] for entry in mapping)

    # Drafts are named as drafts; the pack must not imply conformance with a
    # technical standard that does not exist yet.
    assert {entry["id"] for entry in pack["draft_standards"]} == {
        "prEN 18229-1", "ISO/IEC DIS 24970",
    }
    assert all("draft" in entry["status"] for entry in pack["draft_standards"])
    assert "deployer" in pack["scope_note"]


@requires_stack
def test_manifest_digest_covers_the_manifest(tenant) -> None:
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    from abx_api.compliance import _digest

    pack = fetch_pack(TestClient(app), tenant_id)
    assert _digest(pack) == pack["manifest_digest"]

    forged = {**pack, "retention_policy": {**pack["retention_policy"], "retention_days": 9999}}
    assert _digest(forged) != pack["manifest_digest"]


@requires_stack
def test_invalid_period_is_refused(tenant) -> None:
    tenant_id, _ = tenant
    seeded_tenant(tenant_id)
    response = TestClient(app).get(
        f"/v1/compliance/pack?tenant_id={tenant_id}"
        "&period_from=2027-01-01T00:00:00Z&period_to=2026-01-01T00:00:00Z",
        headers=ADMIN,
    )
    assert response.status_code == 422
