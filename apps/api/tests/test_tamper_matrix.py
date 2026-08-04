"""Every tamper class, against both verifiers (plansecurity SP-7).

The gate names seven ways to alter a chain - mutate, remove, reorder,
duplicate, truncate, insert, cross-tenant-splice - and requires that both the
service verifier and the standalone one fail at the first divergence.

Two verifiers matter because they are the two things a customer relies on and
they share no code. `verify_chain` is what the product says about itself;
`tools/abx_verify.py` is what an auditor runs on an exported bundle with no
network and no Leaflyst service. A tamper detected by one and not the other is
a tamper that survives whichever check the reader happens to trust.

One result here is negative and stated as such: chain walking cannot detect
truncation at the END, because a valid prefix is a valid chain. That is what
the anchor is for, and the test asserts the anchor catches it rather than
implying the chain does.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from abx_api.chain import row_to_event, verify_chain
from abx_api.ingest import ingest_events
from abx_api.main import app
from abx_api.settings import settings
from abx_api.store import ch_client, s3_client
from abx_schemas import IngestEvent
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient

VERIFY_PATH = Path(__file__).parents[3] / "tools" / "abx_verify.py"
SPEC = importlib.util.spec_from_file_location("abx_tamper_verify", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)
verifier_main = VERIFIER.main

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}
CHAIN_LENGTH = 5


def an_event(session_id: str, seq: int) -> IngestEvent:
    return IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "tamper-agent",
        "session_id": session_id, "seq": seq,
        "ts": "2026-08-01T00:00:00.000Z", "source": "mcp_tap",
        "event_type": "tool_call",
        "operation": {"name": f"step {seq}", "provider": "aws", "target": "t",
                      "outcome": "success", "duration_ms": 1},
        "resource_refs": [f"aws:s3:object-{seq}"], "payload": f"body {seq}",
    })


def canonical_events(tenant_id: str) -> list[dict[str, Any]]:
    rows = ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(t)s ORDER BY chain_seq",
        parameters={"t": tenant_id},
    ).named_results()
    return [row_to_event(dict(row)) for row in rows]


def _make_tenant(conn, label: str) -> str:
    from abx_api.auth import new_ingest_token

    row = conn.execute(
        "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
        (f"{label}-{uuid.uuid4().hex[:8]}",),
    ).fetchone()
    assert row is not None
    tenant_id = str(row[0])
    _token, token_hash = new_ingest_token()
    conn.execute(
        "INSERT INTO ingest_tokens (tenant_id, token_hash, label) VALUES (%s,%s,'tamper')",
        (tenant_id, token_hash),
    )
    return tenant_id


@pytest.fixture
def two_chains():
    """One chain to tamper with, and a second real one to splice from.

    The splice source has to be a genuine chain: an invented event would be
    caught by its own hash and would prove nothing about whether a VALID event
    from elsewhere is rejected.
    """
    from abx_api.store import ensure_buckets

    ensure_buckets()
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        victim = _make_tenant(conn, "tamper")
        other = _make_tenant(conn, "splice")

    session_id = f"tamper-{uuid.uuid4().hex[:8]}"
    ingest_events(victim, [an_event(session_id, seq) for seq in range(CHAIN_LENGTH)])
    ingest_events(other, [an_event(f"other-{uuid.uuid4().hex[:8]}", 0)])
    try:
        yield victim, other
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
            for tenant_id in (victim, other):
                _delete_tenant_data(conn, tenant_id)
                conn.execute("DELETE FROM tenants WHERE id=%s", (tenant_id,))


# -- the service verifier ------------------------------------------------------

def _mutate(events: list[dict], foreign: dict) -> list[dict]:
    events[2]["operation"]["target"] = "/production/secrets"
    return events


def _remove(events: list[dict], foreign: dict) -> list[dict]:
    del events[2]
    return events


def _reorder(events: list[dict], foreign: dict) -> list[dict]:
    events[2], events[3] = events[3], events[2]
    return events


def _duplicate(events: list[dict], foreign: dict) -> list[dict]:
    events.insert(3, copy.deepcopy(events[2]))
    return events


def forged_event(template: dict) -> dict:
    """An event the attacker fabricated and hashed correctly themselves.

    The hashing algorithm is public, so an inserted event carrying a WRONG
    self-hash is the easy case. This is the hard one: same tenant, plausible
    content, and an event_hash that recomputes. Only the prev_hash linkage can
    reject it, which is the property the chain actually provides.
    """
    from abx_api.chain import compute_event_hash

    forged = copy.deepcopy(template)
    forged["event_id"] = str(uuid.uuid4())
    forged["operation"] = {**forged["operation"], "name": "step inserted by hand"}
    forged["event_hash"] = compute_event_hash(forged)
    return forged


def _insert(events: list[dict], foreign: dict) -> list[dict]:
    # Same tenant, self-consistent hash: if this were a foreign tenant's event
    # the tenant check would catch it and the link check would never be tested.
    events.insert(2, forged_event(events[1]))
    return events


def _splice(events: list[dict], foreign: dict) -> list[dict]:
    events[2] = copy.deepcopy(foreign)
    return events


TAMPERS = {
    "mutate": _mutate,
    "remove": _remove,
    "reorder": _reorder,
    "duplicate": _duplicate,
    "insert": _insert,
    "cross-tenant-splice": _splice,
}


@requires_stack
@pytest.mark.parametrize("name", sorted(TAMPERS))
def test_the_service_verifier_fails_at_the_first_divergence(name, two_chains) -> None:
    victim, other = two_chains
    clean = canonical_events(victim)
    assert len(clean) == CHAIN_LENGTH, "the chain under test was not built"
    valid, divergent = verify_chain(clean)
    assert valid and divergent is None, "the untampered chain does not verify"

    foreign = canonical_events(other)[0]
    tampered = TAMPERS[name](copy.deepcopy(clean), foreign)

    valid, divergent = verify_chain(tampered)
    assert valid is False, f"{name} was not detected"
    # First divergence, not merely some failure: a verifier that reports the
    # last event cannot tell a responder where the record stops being trustworthy.
    assert divergent == tampered[2]["event_id"], (
        f"{name} reported divergence at {divergent}, expected index 2"
    )


@requires_stack
def test_truncating_the_tail_is_caught_by_the_anchor_not_the_chain(two_chains) -> None:
    """The honest negative result, and the reason the anchor exists.

    A prefix of a valid chain is itself a valid chain: every hash still
    recomputes and every link still matches. Chain walking alone therefore
    cannot see that events were cut from the end, which is the tamper an
    attacker who wants to hide their last action would actually choose.

    What catches it is comparing the head against an independently recorded
    anchor. Asserting only "verify_chain returns False" here would have been
    impossible; asserting it returns True and the anchor disagrees is the
    property that actually holds.
    """
    victim, _other = two_chains
    clean = canonical_events(victim)
    truncated = clean[:-2]

    valid, divergent = verify_chain(truncated)
    assert valid is True and divergent is None, (
        "a valid prefix should still verify; if this changed, the comment above is stale"
    )

    assert truncated[-1]["event_hash"] != clean[-1]["event_hash"]
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        head = conn.execute(
            "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id=%s", (victim,)
        ).fetchone()
    assert head is not None
    assert str(head[0]) == clean[-1]["event_hash"], "the recorded head is not the real head"
    assert int(head[1]) == CHAIN_LENGTH, "the recorded length is not the real length"
    # The truncation is visible precisely because the head is recorded elsewhere.
    assert len(truncated) < int(head[1])


# -- the standalone verifier, on an exported bundle ----------------------------

def _export(tenant_id: str) -> tuple[list[dict], str]:
    """Export the bundle an auditor would be handed, plus its trusted anchor."""
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        head = conn.execute(
            "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
    assert head is not None
    s3_client().put_object(
        Bucket=settings.anchor_bucket,
        Key=f"{tenant_id}/portable-evidence.json",
        Body=json.dumps({
            "tenant_id": tenant_id, "head_hash": head[0], "head_seq": head[1],
            "anchored_at": datetime.now(UTC).isoformat(),
        }).encode(),
    )
    exported = TestClient(app).get(
        "/v1/evidence/tenant", params={"tenant_id": tenant_id}, headers=ADMIN
    )
    assert exported.status_code == 200, exported.text[:200]
    records = [json.loads(line) for line in exported.text.splitlines()]
    return records, str(records[-1]["anchor"]["head_hash"])


def _write(path: Path, records: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
    return path


def _events_of(records: list[dict]) -> list[int]:
    return [i for i, r in enumerate(records) if r.get("type") == "event"]


#: What each tamper must be rejected FOR.
#:
#: Exit code 1 alone is not evidence: the verifier also returns 1 for a missing
#: file or unparseable JSON, so a test that only checks the code would pass on a
#: bundle mangled by the test itself. Pinning the reason also keeps the classes
#: distinct - an earlier version of the insert case planted a foreign tenant's
#: event, so it was rejected by the tenant check and the link check it was
#: supposed to exercise never ran.
EXPECTED_REASON = {
    "mutate": "event hash does not match canonical content",
    "remove": "chain sequence is not contiguous",
    "reorder": "chain sequence is not contiguous",
    "duplicate": "chain sequence is not contiguous",
    "insert": "previous-hash link is broken",
    "cross-tenant-splice": "event tenant does not match",
    "truncate": "checkpoint does not match the streamed chain",
}


@requires_stack
@pytest.mark.parametrize("name", sorted(TAMPERS) + ["truncate"])
def test_the_standalone_verifier_rejects_every_tamper_class(
    name, two_chains, tmp_path, capsys
) -> None:
    """The auditor's copy, with no network and no Leaflyst service.

    This is the check that has to hold when the product is not there to be
    asked - which is the only situation in which tamper evidence is worth
    anything.
    """
    victim, other = two_chains
    records, trusted = _export(victim)
    assert verifier_main([str(_write(tmp_path / "clean.ndjson", records)),
                          "--anchor-hash", trusted]) == 0, (
        "the untampered bundle does not verify, so nothing below proves anything"
    )

    positions = _events_of(records)
    assert len(positions) == CHAIN_LENGTH, positions
    target = positions[2]
    tampered = copy.deepcopy(records)

    if name == "truncate":
        # Cut the tail but keep the footer, which is how a bundle would be
        # trimmed to hide the last actions while still looking well-formed.
        tampered = tampered[: positions[-2]] + [tampered[-1]]
    elif name == "mutate":
        tampered[target]["event"]["operation"]["target"] = "/production/secrets"
    elif name == "remove":
        del tampered[target]
    elif name == "reorder":
        tampered[target], tampered[target + 1] = tampered[target + 1], tampered[target]
    elif name == "duplicate":
        tampered.insert(target + 1, copy.deepcopy(tampered[target]))
    elif name == "insert":
        # Same tenant, self-consistent hash - the attacker can run the same
        # algorithm the verifier does. A foreign event here would be rejected by
        # the tenant check and the link check would go untested.
        planted = copy.deepcopy(tampered[target])
        planted["event"] = forged_event(planted["event"])
        tampered.insert(target, planted)
        for offset, record in enumerate(tampered[target:], start=planted["chain_seq"]):
            if record.get("type") == "event":
                record["chain_seq"] = offset
    else:  # cross-tenant-splice
        foreign_records, _ = _export(other)
        foreign = copy.deepcopy(foreign_records[_events_of(foreign_records)[0]])
        foreign["chain_seq"] = tampered[target]["chain_seq"]
        tampered[target] = foreign

    capsys.readouterr()
    assert verifier_main([str(_write(tmp_path / "bad.ndjson", tampered)),
                          "--anchor-hash", trusted]) == 1, f"{name} was accepted"
    reported = capsys.readouterr().out
    assert EXPECTED_REASON[name] in reported, (
        f"{name} was rejected, but for the wrong reason: {reported.strip()!r}"
    )


@requires_stack
def test_the_standalone_verifier_needs_no_service_or_network(two_chains, tmp_path) -> None:
    """Offline verification is an exit criterion, so it is asserted rather than
    assumed from the verifier living in its own file.

    The check is behavioural: every outbound socket is refused for the duration
    of the run. If the verifier reached for the API, an anchor bucket, or a
    package index, it would fail here rather than quietly succeed because the
    services happened to be up on the machine running the tests.
    """
    import socket

    victim, _other = two_chains
    records, trusted = _export(victim)
    path = _write(tmp_path / "offline.ndjson", records)

    real_socket = socket.socket
    real_create = socket.create_connection

    def refuse(*_args: object, **_kwargs: object):
        raise OSError("network access is not permitted during offline verification")

    socket.socket = refuse  # type: ignore[assignment,misc]
    socket.create_connection = refuse  # type: ignore[assignment]
    try:
        assert verifier_main([str(path), "--anchor-hash", trusted]) == 0
    finally:
        socket.socket = real_socket  # type: ignore[misc]
        socket.create_connection = real_create
