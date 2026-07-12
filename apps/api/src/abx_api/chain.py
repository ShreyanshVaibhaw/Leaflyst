"""Hash-chain core: canonical serialization, hashing, and CH row mapping.

The canonical form of an event is the single source of truth for hashing.
Ingest, the verify endpoint, and the standalone abx-verify script must all
produce byte-identical canonical JSON for the same event, or verification
breaks. Rules:

- JSON object with keys sorted, compact separators, UTF-8.
- ts is an RFC3339 string in UTC with exactly millisecond precision and a
  'Z' suffix (events are normalized to this at ingest).
- UUIDs are lowercase hyphenated strings.
- event_hash is sha256 over the canonical JSON of every field EXCEPT
  event_hash itself. The payload body is NOT hashed; payload_digest is.

GENESIS_HASH (sha256 of the empty string) is the prev_hash of each tenant's
first event.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from abx_schemas.generated.contract import HASHED_FIELDS

GENESIS_HASH = hashlib.sha256(b"").hexdigest()

def format_ts(ts: datetime) -> str:
    """RFC3339, UTC, exactly millisecond precision, Z suffix."""
    ts = ts.astimezone(UTC)
    ms = ts.microsecond // 1000
    return ts.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def canonical_json(event: dict[str, Any]) -> bytes:
    """Canonical bytes of an event dict (event_hash excluded if present)."""
    doc = {k: event[k] for k in HASHED_FIELDS}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_event_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(event)).hexdigest()


def event_to_row(event: dict[str, Any], chain_seq: int) -> list[Any]:
    """Canonical event dict -> ClickHouse row (store.EVENT_COLUMNS order)."""
    op = event["operation"]
    return [
        event["event_id"], event["tenant_id"], event["agent_id"], event["session_id"],
        event["seq"],
        datetime.strptime(event["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC),
        event["source"], event["event_type"],
        op["name"], op.get("provider") or "", op.get("target") or "", op["outcome"],
        op.get("duration_ms"),
        event.get("credential_ref") or "", event["resource_refs"],
        event["payload_digest"], event.get("payload_ref") or "",
        event["payload_truncated"], event["redactions"],
        event["prev_hash"], event["event_hash"], chain_seq,
    ]


def row_to_event(row: dict[str, Any]) -> dict[str, Any]:
    """ClickHouse row (as dict) -> canonical event dict, ready for re-hashing.

    Empty-string sentinels in CH map back to null; FixedString columns may
    come back as bytes.
    """

    def _s(v: Any) -> str:
        return v.decode() if isinstance(v, bytes) else str(v)

    ts = row["ts"]
    if not isinstance(ts, datetime):
        ts = datetime.fromisoformat(str(ts))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return {
        "event_id": _s(row["event_id"]),
        "tenant_id": _s(row["tenant_id"]),
        "agent_id": row["agent_id"],
        "session_id": row["session_id"],
        "seq": row["seq"],
        "ts": format_ts(ts),
        "source": row["source"],
        "event_type": row["event_type"],
        "operation": {
            "name": row["op_name"],
            "provider": row["op_provider"] or None,
            "target": row["op_target"] or None,
            "outcome": row["op_outcome"],
            "duration_ms": row["op_duration_ms"],
        },
        "credential_ref": row["credential_ref"] or None,
        "resource_refs": list(row["resource_refs"]),
        "payload_digest": _s(row["payload_digest"]),
        "payload_ref": row["payload_ref"] or None,
        "payload_truncated": bool(row["payload_truncated"]),
        "redactions": list(row["redactions"]),
        "prev_hash": _s(row["prev_hash"]),
        "event_hash": _s(row["event_hash"]),
    }


def verify_chain(events: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """Verify a chain-ordered list of canonical events.

    Checks each event's recomputed hash and each link's prev_hash continuity.
    Returns (valid, first_divergent_event_id).
    """
    prev: str | None = None
    for event in events:
        if compute_event_hash(event) != event["event_hash"]:
            return False, str(event["event_id"])
        if prev is not None and event["prev_hash"] != prev:
            return False, str(event["event_id"])
        prev = event["event_hash"]
    return True, None
