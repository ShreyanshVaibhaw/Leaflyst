#!/usr/bin/env python3
"""Verify an Leaflyst evidence bundle using only the Python standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS_HASH = hashlib.sha256(b"").hexdigest()
# BEGIN GENERATED HASHED FIELDS
HASHED_FIELDS_BY_VERSION = {
    1: [
        "event_id",
        "tenant_id",
        "agent_id",
        "session_id",
        "seq",
        "ts",
        "source",
        "event_type",
        "operation",
        "credential_ref",
        "resource_refs",
        "payload_digest",
        "payload_ref",
        "payload_truncated",
        "redactions",
        "prev_hash",
    ],
    2: [
        "agent_id",
        "credential_ref",
        "event_id",
        "event_type",
        "operation",
        "operator_ref",
        "payload_digest",
        "payload_ref",
        "payload_truncated",
        "prev_hash",
        "redactions",
        "resource_refs",
        "schema_version",
        "seq",
        "session_id",
        "source",
        "tenant_id",
        "ts",
    ],
}
CURRENT_SCHEMA_VERSION = 2
# END GENERATED HASHED FIELDS


@dataclass(frozen=True)
class Verification:
    valid: bool
    events_checked: int
    first_divergent_event_id: str | None
    checkpoint_verified: bool
    anchor_verified: bool | None
    trusted_anchor_verified: bool | None
    message: str


def hashed_fields_for(event: dict[str, Any]) -> list[str]:
    """The field set this event is hashed under, chosen by its own version.

    An event with no schema_version is version 1, the original field set. From
    version 2 the version is itself hashed, so stripping or forging it changes
    the computed hash and fails verification rather than switching how the
    event is read. This is what lets one evidence stream contain events written
    before and after a schema change and still verify as a single chain.
    """
    version = event.get("schema_version", 1)
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("schema_version must be an integer")
    fields = HASHED_FIELDS_BY_VERSION.get(version)
    if fields is None:
        raise ValueError(f"unknown canonical event schema version {version}")
    return fields


def event_hash(event: dict[str, Any]) -> str:
    canonical = json.dumps(
        {field: event[field] for field in hashed_fields_for(event)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _failure(checked: int, event_id: str | None, message: str) -> Verification:
    return Verification(False, checked, event_id, False, None, None, message)


def verify_file(path: Path, trusted_head: str, legacy_jsonl: bool = False) -> Verification:
    """Verify an evidence stream incrementally, using constant memory."""
    with path.open(encoding="utf-8") as stream:
        if legacy_jsonl:
            tenant_id = ""
        else:
            first = stream.readline()
            header = json.loads(first)
            if not isinstance(header, dict) or header.get("type") != "header":
                return _failure(0, None, "evidence header is missing")
            if header.get("format") != "abx-evidence-v1":
                return _failure(0, None, "unsupported evidence format")
            tenant_id = str(header.get("tenant_id", ""))

        previous = GENESIS_HASH
        count = 0
        footer: dict[str, Any] | None = None
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                return _failure(count, None, "evidence record is not an object")
            if not legacy_jsonl and record.get("type") == "footer":
                footer = record
                break
            event = record if legacy_jsonl else record.get("event")
            if not isinstance(event, dict):
                return _failure(count, None, "canonical event is not an object")
            event_id = str(event.get("event_id", "")) or None
            count += 1
            if not legacy_jsonl and record.get("chain_seq") != count:
                return _failure(count - 1, event_id, "chain sequence is not contiguous")
            event_tenant = str(event.get("tenant_id", ""))
            if count == 1 and legacy_jsonl:
                tenant_id = event_tenant
            if event_tenant != tenant_id:
                return _failure(count - 1, event_id, "event tenant does not match")
            if event.get("prev_hash") != previous:
                return _failure(count - 1, event_id, "previous-hash link is broken")
            try:
                computed = event_hash(event)
            except (KeyError, TypeError, ValueError):
                return _failure(count - 1, event_id, "event is missing canonical fields")
            if event.get("event_hash") != computed:
                return _failure(count - 1, event_id, "event hash does not match canonical content")
            previous = computed

        if count == 0:
            return _failure(0, None, "evidence stream has no events")
        normalized = trusted_head.lower()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            return _failure(count, None, "trusted anchor hash is not SHA-256 hex")
        if legacy_jsonl:
            if previous != normalized:
                return _failure(count, None, "trusted chain head does not match the stream")
            return Verification(
                True, count, None, True, None, True, "chain and trusted head are valid"
            )
        if footer is None:
            return _failure(count, None, "evidence footer is missing")
        if any(line.strip() for line in stream):
            return _failure(count, None, "records follow the evidence footer")
        checkpoint = footer.get("checkpoint")
        anchor = footer.get("anchor")
        checkpoint_ok = (
            isinstance(checkpoint, dict)
            and checkpoint.get("head_seq") == count
            and checkpoint.get("head_hash") == previous
        )
        anchor_ok = (
            isinstance(anchor, dict)
            and str(anchor.get("tenant_id", "")) == tenant_id
            and anchor.get("head_seq") == count
            and anchor.get("head_hash") == previous
        )
        if not checkpoint_ok:
            return _failure(count, None, "checkpoint does not match the streamed chain")
        if not anchor_ok:
            return _failure(count, None, "anchor does not cover the streamed checkpoint")
        if previous != normalized:
            return _failure(count, None, "trusted anchor hash does not match the stream")
        return Verification(
            True,
            count,
            None,
            True,
            True,
            True,
            "chain, checkpoint, and independently supplied anchor are valid",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="abx-verify")
    parser.add_argument("bundle", type=Path, help="path to an abx-evidence-v1 JSON file")
    trust = parser.add_mutually_exclusive_group(required=True)
    trust.add_argument(
        "--anchor-hash",
        help="trusted anchor SHA-256 hash obtained independently from the evidence bundle",
    )
    trust.add_argument(
        "--expect-head",
        help="trusted chain head for legacy canonical-event JSONL exports",
    )
    args = parser.parse_args(argv)
    try:
        trusted_head = args.expect_head or args.anchor_hash
        result = verify_file(args.bundle, trusted_head, legacy_jsonl=bool(args.expect_head))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    prefix = "VALID" if result.valid else "INVALID"
    if result.valid and args.expect_head:
        print(f"{result.events_checked} events verified; trusted head matches")
    else:
        print(f"{prefix}: {result.message}; events checked: {result.events_checked}")
    if result.first_divergent_event_id:
        print(f"first divergent event: {result.first_divergent_event_id}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
