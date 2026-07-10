import hashlib
import json
from pathlib import Path

import pytest
from abx_schemas import CanonicalEvent
from pydantic import ValidationError

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

EXAMPLE = {
    "event_id": "0197b7e2-7c3a-7000-8000-000000000001",
    "tenant_id": "6f1d9c2e-4b7a-4c1d-9e2f-1a2b3c4d5e6f",
    "agent_id": "billing-bot",
    "session_id": "sess-001",
    "seq": 0,
    "ts": "2026-07-10T12:00:00.000Z",
    "source": "mcp_tap",
    "event_type": "mcp_request",
    "operation": {
        "name": "tools/call delete_volume",
        "provider": "railway-mcp",
        "target": "delete_volume",
        "outcome": "success",
        "duration_ms": 42,
    },
    "credential_ref": "aws:AKIA****EXAMPLE",
    "resource_refs": ["railway:volume:prod-db"],
    "payload_digest": EMPTY_SHA256,
    "payload_ref": None,
    "payload_truncated": False,
    "redactions": ["aws-secret-key"],
    "prev_hash": EMPTY_SHA256,
    "event_hash": hashlib.sha256(b"placeholder").hexdigest(),
}


def test_example_event_roundtrip() -> None:
    event = CanonicalEvent.model_validate(EXAMPLE)
    assert event.agent_id == "billing-bot"
    again = CanonicalEvent.model_validate(json.loads(event.model_dump_json()))
    assert again == event


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate({**EXAMPLE, "surprise": 1})


def test_bad_hash_rejected() -> None:
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate({**EXAMPLE, "event_hash": "not-a-hash"})


def test_schema_file_parses() -> None:
    schema_path = Path(__file__).parents[1] / "schema" / "event.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["title"] == "CanonicalEvent"
    assert schema["additionalProperties"] is False
