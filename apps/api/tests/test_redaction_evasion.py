"""Adversarial redaction evasion (plansecurity SP-6c).

LYS-RED-01's sweep proves known patterns are caught. That is a different claim
from "a secret cannot survive", and the difference has bitten this project
before: the token rules originally carried word-boundary anchors, so a secret
glued to adjacent text passed through untouched.

Redaction is regex-based and server-side, so evasion is a design question
rather than a bug hunt. Each case below is either caught, or the reason it
cannot be is stated in the test that shows what actually happens - a silent
gap is worse than a known one.
"""

from __future__ import annotations

import base64
import uuid

import psycopg
import pytest
from abx_api.ingest import _scrub_metadata, ingest_events
from abx_api.main import app
from abx_api.redaction import redact, redact_and_truncate
from abx_api.settings import settings
from abx_api.store import ch_client
from abx_schemas import IngestEvent
from conftest import _delete_tenant_data, requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-ABX-Admin-Key": "dev-admin-key"}

#: Synthetic. Structurally valid, never issued.
PAT = "ghp_" + "e" * 36
BODY = "e" * 36
AWS_KEY_ID = "AKIA" + "R" * 16


def event(**overrides) -> IngestEvent:
    base = {
        "event_id": str(uuid.uuid4()), "agent_id": "evasion-agent",
        "session_id": f"ev-{uuid.uuid4().hex[:8]}", "seq": 0,
        "ts": "2026-08-01T00:00:00.000Z", "source": "mcp_tap",
        "event_type": "tool_call",
        "operation": {"name": "call", "provider": "aws", "target": "t",
                      "outcome": "success", "duration_ms": 1},
        "resource_refs": ["aws:s3:bucket"], "payload": None,
    }
    operation = {**base["operation"], **overrides.pop("operation", {})}
    return IngestEvent.model_validate({**base, **overrides, "operation": operation})


# -- a secret in a field the pipeline does not treat as payload ----------------

METADATA_CASES = {
    "operation.name": {"operation": {"name": f"POST /repos?token={PAT}"}},
    "operation.target": {"operation": {"target": PAT}},
    "resource_refs": {"resource_refs": [f"github:repo:{PAT}"]},
    "agent_id": {"agent_id": f"agent-{PAT}"},
    "session_id": {"session_id": f"sess-{PAT}"},
    "credential_ref": {"credential_ref": PAT},
}


@pytest.mark.parametrize("field", sorted(METADATA_CASES))
def test_a_secret_outside_the_payload_is_still_scrubbed(field: str) -> None:
    """"Never store secret values anywhere" is about the record, not one field.

    Redaction ran on payload and credential_ref, which left every other string
    the agent controls holding whatever it was handed. None of this needs an
    attacker: an agent that names an operation after the URL it called, or
    derives a session id from a request that carried a token, leaks by accident.
    """
    scrubbed, fired = _scrub_metadata(event(**METADATA_CASES[field]))
    assert fired == ["github-token"], f"{field} did not fire the rule"
    assert PAT not in scrubbed.model_dump_json(), f"{field} kept the raw token"


def test_the_metadata_scrub_would_be_visible_if_it_were_removed() -> None:
    """The negative control. If the input did not carry the secret, every
    assertion above would pass with the scrub deleted."""
    hostile = event(agent_id=f"agent-{PAT}", operation={"target": PAT})
    assert PAT in hostile.model_dump_json(), "the input must carry the secret"
    scrubbed, fired = _scrub_metadata(hostile)
    assert scrubbed.model_dump_json() != hostile.model_dump_json()
    assert fired


def test_a_credential_fingerprint_still_passes_through_untouched() -> None:
    """The SP-6 lesson, re-asserted for the fields added here.

    An AWS access key id is the PUBLIC half of the pair and is exactly what
    credentials.fingerprint stores. Scrubbing it from a resource ref would break
    blast radius while protecting nothing.
    """
    untouched, fired = _scrub_metadata(
        event(resource_refs=[f"aws:iam:{AWS_KEY_ID}"], agent_id=AWS_KEY_ID)
    )
    assert fired == []
    assert AWS_KEY_ID in untouched.model_dump_json()


# -- how the secret is written -------------------------------------------------

@pytest.mark.parametrize("label,written", [
    ("glued with no delimiter either side", f"prefix{PAT}suffix"),
    ("zero-width space inside", PAT[:10] + "​" + PAT[10:]),
    ("zero-width joiner inside", PAT[:20] + "‍" + PAT[20:]),
    ("soft hyphen inside", PAT[:10] + "­" + PAT[10:]),
    ("combining accent inside", PAT[:10] + "́" + PAT[10:]),
    ("right-to-left override inside", PAT[:10] + "‮" + PAT[10:]),
    ("byte order mark inside", PAT[:10] + "﻿" + PAT[10:]),
    ("full-width homoglyph prefix", "ｇｈｐ_" + BODY),
])
def test_a_secret_written_to_dodge_the_pattern_is_still_caught(
    label: str, written: str
) -> None:
    """These render as the token and paste as the token; only the regex
    disagrees. They arrive by accident more often than by attack - copying a
    credential out of a rendered page or a terminal picks them up silently.
    """
    scrubbed, fired = redact(written)
    assert fired == ["github-token"], f"{label} evaded every rule"
    assert BODY not in scrubbed, f"{label} left the secret body in place"


def test_folding_does_not_eat_the_text_around_the_secret() -> None:
    """The reason the fold carries an index map rather than scrubbing a
    normalised copy: the copy is not what gets stored. Redacting it would leave
    the original - the real record - still holding the secret, and would also
    silently rewrite every other character in the payload.
    """
    written = f"agent used {PAT[:10]}​{PAT[10:]} against the API"
    scrubbed, fired = redact(written)
    assert fired == ["github-token"]
    assert scrubbed == "agent used [REDACTED:github-token:eeee] against the API"


def test_ordinary_unicode_is_not_redacted() -> None:
    """The fold must not turn accented prose into a redaction."""
    for benign in ("naïve café", "日本語のテキスト", "é combining", "a​b"):
        scrubbed, fired = redact(benign)
        assert fired == [], (benign, fired)
        assert scrubbed == benign, "benign text was rewritten"


# -- the truncation boundary ---------------------------------------------------

def test_a_secret_straddling_the_truncation_cut_is_scrubbed_first() -> None:
    """The exit criterion names this ordering explicitly.

    Truncating first would cut the token in half and leave the head - still
    most of the secret - stored in the clear, because the remaining fragment no
    longer matches the rule that would have caught it.
    """
    filler = "x" * 40
    body, fired, truncated = redact_and_truncate(filler + PAT, max_bytes=len(filler) + 10)
    assert truncated is True, "the case under test did not truncate"
    assert fired == ["github-token"]
    assert BODY[:6] not in body.decode(), "the head of the secret survived the cut"

    # Same input, cut first: shows what the ordering is protecting against.
    cut_first, fired_after = redact((filler + PAT)[: len(filler) + 10])
    assert fired_after == [], "the fragment still matched, so this proves nothing"
    assert PAT[:10] in cut_first, "truncate-then-scrub would have kept this"


# -- cases that cannot be caught, and why --------------------------------------

def test_a_secret_split_across_fields_is_not_reassembled() -> None:
    """Recorded as a known limit, with the reason it is an acceptable one.

    Neither half is a credential: `ghp_` plus eighteen characters does not match
    any rule and will not authenticate anywhere. Catching this would mean
    concatenating every combination of every field and rescanning, which is
    quadratic and would still miss a split across two events.

    It is also the wrong threat. Redaction protects against a secret reaching
    the record BY ACCIDENT. Splitting one across fields is not something an
    agent does by accident - it is something an attacker does deliberately, and
    an attacker doing it already holds the secret. They gain nothing by storing
    half of it in a system they must authenticate to read back.
    """
    half_a, half_b = PAT[:20], PAT[20:]
    for half in (half_a, half_b):
        _scrubbed, fired = redact(half)
        assert fired == [], "a half matched a rule, so this test is out of date"
    assert half_a + half_b == PAT


@pytest.mark.parametrize("label,encoded", [
    ("base64", base64.b64encode(PAT.encode()).decode()),
    ("hex", PAT.encode().hex()),
    ("double base64", base64.b64encode(base64.b64encode(PAT.encode())).decode()),
])
def test_an_encoded_secret_is_not_decoded_and_rescanned(label: str, encoded: str) -> None:
    """The other known limit, and the one worth being most explicit about.

    Decoding every base64-shaped run and rescanning would catch this. It would
    also decode the large volume of legitimately encoded data this product
    records, at every level, on every payload - and a recorder that rewrites its
    own evidence on a guess about the encoding is a worse failure than the one
    it prevents.

    The compensating control is that payload bodies are envelope-encrypted at
    rest and reachable only through tenant-scoped, capability-checked routes, so
    an encoded secret in a payload is not readable without an authorised token.
    That is a weaker guarantee than redaction and is recorded as such in
    docs/security-risk-acceptances.md rather than left implied.
    """
    _scrubbed, fired = redact(encoded)
    assert fired == [], f"{label} now fires a rule; update the acceptance"
    assert PAT not in encoded, "the encoding is a no-op, so this proves nothing"


# -- end to end ----------------------------------------------------------------

@pytest.fixture
def evasion_tenant():
    from abx_api.auth import new_ingest_token
    from abx_api.store import ensure_buckets

    ensure_buckets()
    with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
        row = conn.execute(
            "INSERT INTO tenants (name) VALUES (%s) RETURNING id",
            (f"evasion-{uuid.uuid4().hex[:8]}",),
        ).fetchone()
        assert row is not None
        tenant_id = str(row[0])
        token, token_hash = new_ingest_token()
        conn.execute(
            "INSERT INTO ingest_tokens (tenant_id, token_hash, label) VALUES (%s,%s,'ev')",
            (tenant_id, token_hash),
        )
    try:
        yield tenant_id, token
    finally:
        with psycopg.connect(settings.pg_dsn, autocommit=True) as conn:
            _delete_tenant_data(conn, tenant_id)
            conn.execute("DELETE FROM tenants WHERE id = %s", (tenant_id,))


@requires_stack
def test_no_evaded_form_survives_into_storage_or_replay(evasion_tenant) -> None:
    """The unit assertions above prove the function; this proves the pipeline.

    A rule that fires in isolation is worth nothing if the value reaching
    ClickHouse came down a path that skipped it.
    """
    tenant_id, _ = evasion_tenant
    session_id = f"ev-{uuid.uuid4().hex[:8]}"
    ingest_events(tenant_id, [
        event(
            session_id=session_id, seq=0,
            agent_id=f"agent-{PAT[:10]}​{PAT[10:]}",
            operation={"name": f"call {PAT}", "target": f"prefix{PAT}suffix"},
            resource_refs=[f"github:repo:{PAT}"],
            credential_ref=PAT,
            payload=f"body carrying {PAT[:10]}­{PAT[10:]}",
        ),
    ])

    stored = ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(t)s", parameters={"t": tenant_id}
    ).result_rows
    assert stored, "nothing reached ClickHouse, so this sweep proves nothing"
    assert BODY not in str(stored), "an evaded form reached storage"

    client = TestClient(app)
    replay = client.get(
        f"/v1/replay/sessions/{session_id}", params={"tenant_id": tenant_id}, headers=ADMIN
    )
    assert replay.status_code == 200, replay.text[:200]
    assert session_id in replay.text, "replay returned nothing about this session"
    assert BODY not in replay.text, "replay echoed an evaded form"
