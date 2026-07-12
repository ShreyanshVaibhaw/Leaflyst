from __future__ import annotations

import copy
import importlib.util
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import s3_client
from abx_schemas import EvidenceRecord
from conftest import requires_stack
from fastapi.testclient import TestClient

VERIFY_PATH = Path(__file__).parents[3] / "tools" / "abx_verify.py"
SPEC = importlib.util.spec_from_file_location("abx_standalone_verify", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)
verifier_main = VERIFIER.main


@requires_stack
def test_exported_bundle_verifies_offline_and_detects_tampering(tenant, tmp_path) -> None:
    tenant_id, token = tenant
    session_id = "portable-evidence-session"
    events = []
    for seq, operation in enumerate(("read_file", "delete_file")):
        events.append({
            "event_id": str(uuid.uuid4()),
            "agent_id": "evidence-agent",
            "session_id": session_id,
            "seq": seq,
            "ts": datetime.now(UTC).isoformat(),
            "source": "mcp_tap",
            "event_type": "file_op",
            "operation": {
                "name": operation, "provider": "filesystem", "target": "/sandbox/file",
                "outcome": "success", "duration_ms": seq + 1,
            },
            "credential_ref": None,
            "resource_refs": ["/sandbox/file"],
            "payload": "captured body is excluded from the portable bundle",
        })
    client = TestClient(app)
    ingested = client.post(
        "/v1/ingest", json={"events": events},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ingested.status_code == 200, ingested.text
    with psycopg.connect(settings.pg_dsn) as conn:
        head = conn.execute(
            "SELECT head_hash,head_seq FROM chain_heads WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
        assert head is not None
    anchor_key = f"{tenant_id}/portable-evidence.json"
    s3_client().put_object(
        Bucket=settings.anchor_bucket,
        Key=anchor_key,
        Body=json.dumps({
            "tenant_id": tenant_id, "head_hash": head[0], "head_seq": head[1],
            "anchored_at": datetime.now(UTC).isoformat(),
        }).encode(),
    )
    exported = client.get(
        "/v1/evidence/tenant",
        params={"tenant_id": tenant_id},
        headers={"X-ABX-Admin-Key": "dev-admin-key"},
    )
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-type"].startswith("application/x-ndjson")
    records = [json.loads(line) for line in exported.text.splitlines()]
    for record in records:
        EvidenceRecord.model_validate(record)
    assert records[0]["type"] == "header"
    assert records[-1]["type"] == "footer"
    event_records = [record for record in records if record["type"] == "event"]
    assert all("payload" not in item["event"] for item in event_records)
    trusted_hash = records[-1]["anchor"]["head_hash"]

    path = tmp_path / "evidence.ndjson"
    path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
    assert verifier_main([str(path), "--anchor-hash", trusted_hash]) == 0

    tampered = copy.deepcopy(records)
    tampered[1]["event"]["operation"]["target"] = "/production/secrets"
    path.write_text("\n".join(json.dumps(record) for record in tampered), encoding="utf-8")
    assert verifier_main([str(path), "--anchor-hash", trusted_hash]) == 1
