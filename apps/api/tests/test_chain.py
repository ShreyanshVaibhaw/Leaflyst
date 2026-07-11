from datetime import UTC, datetime

from abx_api.chain import (
    GENESIS_HASH,
    canonical_json,
    compute_event_hash,
    event_to_row,
    format_ts,
    row_to_event,
    verify_chain,
)
from abx_api.store import EVENT_COLUMNS


def make_event(seq: int, prev_hash: str) -> dict:
    event = {
        "event_id": f"0197b7e2-7c3a-7000-8000-00000000000{seq}",
        "tenant_id": "6f1d9c2e-4b7a-4c1d-9e2f-1a2b3c4d5e6f",
        "agent_id": "billing-bot",
        "session_id": "sess-1",
        "seq": seq,
        "ts": "2026-07-10T12:00:00.123Z",
        "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {
            "name": "tools/call x",
            "provider": None,
            "target": "x",
            "outcome": "success",
            "duration_ms": 3,
        },
        "credential_ref": None,
        "resource_refs": ["file:/a"],
        "payload_digest": "0" * 64,
        "payload_ref": None,
        "payload_truncated": False,
        "redactions": [],
        "prev_hash": prev_hash,
    }
    event["event_hash"] = compute_event_hash(event)
    return event


def make_chain(n: int) -> list[dict]:
    events, prev = [], GENESIS_HASH
    for i in range(n):
        e = make_event(i, prev)
        events.append(e)
        prev = e["event_hash"]
    return events


def test_canonical_json_deterministic() -> None:
    e = make_event(0, GENESIS_HASH)
    assert canonical_json(e) == canonical_json(dict(reversed(list(e.items()))))


def test_hash_changes_on_any_field() -> None:
    e = make_event(0, GENESIS_HASH)
    h = compute_event_hash(e)
    for mutation in [
        {"agent_id": "other"},
        {"seq": 1},
        {"payload_digest": "f" * 64},
        {"operation": {**e["operation"], "outcome": "error"}},
    ]:
        assert compute_event_hash({**e, **mutation}) != h


def test_format_ts_ms_precision_utc() -> None:
    ts = datetime(2026, 7, 10, 12, 0, 0, 123999, tzinfo=UTC)
    assert format_ts(ts) == "2026-07-10T12:00:00.123Z"


def test_row_roundtrip_preserves_hash() -> None:
    e = make_event(0, GENESIS_HASH)
    row = dict(zip(EVENT_COLUMNS, event_to_row(e, chain_seq=1), strict=True))
    back = row_to_event(row)
    assert back == e
    assert compute_event_hash(back) == e["event_hash"]


def test_verify_chain_accepts_valid() -> None:
    valid, divergent = verify_chain(make_chain(5))
    assert valid and divergent is None


def test_verify_chain_catches_tamper() -> None:
    events = make_chain(5)
    events[2]["agent_id"] = "evil"
    valid, divergent = verify_chain(events)
    assert not valid
    assert divergent == events[2]["event_id"]


def test_verify_chain_catches_broken_link() -> None:
    events = make_chain(5)
    del events[2]  # missing event breaks continuity at index 3
    valid, divergent = verify_chain(events)
    assert not valid
    assert divergent == events[2]["event_id"]  # former index 3
