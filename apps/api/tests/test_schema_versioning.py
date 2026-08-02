"""Canonical event schema versioning (blueprint2 13.1).

Adding a field to the hashed set would silently invalidate every event written
before it, including anchored ones and already-exported evidence. So the hashed
field set is versioned and selected by the event's own `schema_version`.

Two properties must hold, and the second is a security property:

1. Continuity - a chain spanning a schema change verifies as one chain.
2. Non-malleability - the version cannot be added, stripped, or altered to
   change how an event is read. It is itself hashed from version 2 on, so any
   tampering changes the computed hash instead of the interpretation.

The service and the standalone verifier implement the selection independently;
these tests pin that they agree, because a drift between them would mean
evidence that verifies in-product and fails for an auditor (or worse, the
reverse).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from abx_api.chain import compute_event_hash, hashed_fields_for, verify_chain
from abx_schemas.generated.contract import CURRENT_SCHEMA_VERSION, HASHED_FIELDS_BY_VERSION

VERIFY_PATH = Path(__file__).parents[3] / "tools" / "abx_verify.py"
SPEC = importlib.util.spec_from_file_location("abx_standalone_verify_versions", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)

GENESIS = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def v1_event(**overrides: object) -> dict:
    """An event as written before schema versioning existed."""
    event = {
        "event_id": "0192f0c0-0000-7000-8000-000000000001",
        "tenant_id": "0192f0c0-0000-7000-8000-0000000000aa",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "seq": 0,
        "ts": "2026-07-30T12:00:00.000Z",
        "source": "mcp_tap",
        "event_type": "mcp_request",
        "operation": {
            "name": "tools/call echo", "provider": "fake", "target": "echo",
            "outcome": "success", "duration_ms": 3,
        },
        "credential_ref": None,
        "resource_refs": [],
        "payload_digest": "a" * 64,
        "payload_ref": None,
        "payload_truncated": False,
        "redactions": [],
        "prev_hash": GENESIS + "5",
    }
    event.update(overrides)
    return event


def v2_event(**overrides: object) -> dict:
    event = v1_event(schema_version=2, operator_ref="operator-7")
    event.update(overrides)
    return event


def sealed(event: dict) -> dict:
    return {**event, "event_hash": compute_event_hash(event)}


# -- field-set selection -----------------------------------------------------

def test_absent_version_is_the_historic_field_set() -> None:
    assert hashed_fields_for(v1_event()) == HASHED_FIELDS_BY_VERSION[1]
    assert "operator_ref" not in HASHED_FIELDS_BY_VERSION[1]


def test_version_two_hashes_the_new_fields() -> None:
    fields = hashed_fields_for(v2_event())
    assert fields == HASHED_FIELDS_BY_VERSION[2]
    assert "operator_ref" in fields
    # The version must be inside its own hashed set or it could be swapped.
    assert "schema_version" in fields


def test_version_one_field_set_is_frozen() -> None:
    """Version 1 describes events already written and anchored. Changing it
    would retroactively invalidate history, so it is not editable."""
    assert HASHED_FIELDS_BY_VERSION[1] == (
        "event_id", "tenant_id", "agent_id", "session_id", "seq", "ts", "source",
        "event_type", "operation", "credential_ref", "resource_refs",
        "payload_digest", "payload_ref", "payload_truncated", "redactions", "prev_hash",
    )


def test_unknown_version_is_refused_not_guessed() -> None:
    with pytest.raises(ValueError, match="unknown canonical event schema version"):
        hashed_fields_for(v1_event(schema_version=99))


def test_non_integer_version_refused() -> None:
    for bad in ("2", 2.0, True, None):
        with pytest.raises(ValueError):
            hashed_fields_for(v1_event(schema_version=bad))


# -- non-malleability --------------------------------------------------------

def test_promoting_a_v1_event_to_v2_breaks_its_hash() -> None:
    """An attacker adding schema_version to an old event must not get it read
    under a different field set - the hash must stop matching."""
    original = sealed(v1_event())
    forged = {**original, "schema_version": 2, "operator_ref": "someone-else"}
    assert compute_event_hash(forged) != forged["event_hash"]
    valid, first = verify_chain([forged])
    assert not valid and first == forged["event_id"]


def test_stripping_the_version_from_a_v2_event_breaks_its_hash() -> None:
    original = sealed(v2_event())
    forged = {k: v for k, v in original.items() if k != "schema_version"}
    forged.pop("operator_ref")
    assert compute_event_hash(forged) != original["event_hash"]


def test_changing_operator_attribution_breaks_the_hash() -> None:
    """Article 12 attribution is only worth something if it cannot be rewritten
    after the fact."""
    original = sealed(v2_event())
    forged = {**original, "operator_ref": "not-the-real-operator"}
    valid, first = verify_chain([forged])
    assert not valid and first == forged["event_id"]


# -- continuity across the upgrade boundary ----------------------------------

def test_a_chain_spanning_the_schema_change_verifies_as_one_chain() -> None:
    first = sealed(v1_event(seq=0, prev_hash=GENESIS + "5"))
    second = sealed(v2_event(
        event_id="0192f0c0-0000-7000-8000-000000000002",
        seq=1, prev_hash=first["event_hash"],
    ))
    valid, divergent = verify_chain([first, second])
    assert valid and divergent is None


def test_tampering_after_the_boundary_still_names_the_first_divergent_event() -> None:
    first = sealed(v1_event(seq=0, prev_hash=GENESIS + "5"))
    second = sealed(v2_event(
        event_id="0192f0c0-0000-7000-8000-000000000002",
        seq=1, prev_hash=first["event_hash"],
    ))
    second["operation"]["outcome"] = "denied"
    valid, divergent = verify_chain([first, second])
    assert not valid and divergent == second["event_id"]


# -- the two implementations must not drift ----------------------------------

def test_standalone_verifier_agrees_on_every_version() -> None:
    """Evidence that verifies in-product must verify for an auditor holding
    only the single-file script, and vice versa."""
    assert VERIFIER.HASHED_FIELDS_BY_VERSION.keys() == HASHED_FIELDS_BY_VERSION.keys()
    for version, fields in HASHED_FIELDS_BY_VERSION.items():
        assert list(fields) == VERIFIER.HASHED_FIELDS_BY_VERSION[version], version
    assert VERIFIER.CURRENT_SCHEMA_VERSION == CURRENT_SCHEMA_VERSION

    for event in (v1_event(), v2_event()):
        assert VERIFIER.event_hash(event) == compute_event_hash(event)


def test_standalone_verifier_refuses_unknown_versions_too() -> None:
    with pytest.raises(ValueError):
        VERIFIER.hashed_fields_for(v1_event(schema_version=99))
