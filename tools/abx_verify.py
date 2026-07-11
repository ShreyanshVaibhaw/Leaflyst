#!/usr/bin/env python3
"""abx-verify: standalone, dependency-free chain verifier.

Verifies an exported AgentBlackBox event chain with NO access to the service:
anyone can independently confirm the record was not tampered with.

Usage:
    python abx_verify.py events.jsonl [--expect-head <sha256>]

The input is JSON Lines: one canonical event per line, in chain order.
Exit code 0 = chain verifies, 1 = verification FAILED, 2 = usage error.

Only the Python standard library is used, on purpose: the verifier must not
require trusting our code distribution chain. Canonical form (must match the
service): JSON with sorted keys and compact separators over every field except
event_hash; sha256 hex; prev_hash of the first event in a full export is
sha256 of the empty string.
"""

import hashlib
import json
import sys

HASHED_FIELDS = [
    "event_id", "tenant_id", "agent_id", "session_id", "seq", "ts",
    "source", "event_type", "operation", "credential_ref", "resource_refs",
    "payload_digest", "payload_ref", "payload_truncated", "redactions",
    "prev_hash",
]


def compute_event_hash(event: dict) -> str:
    doc = {k: event[k] for k in HASHED_FIELDS}
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def main(argv: list) -> int:
    expect_head = None
    positional = []
    rest = argv[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "--expect-head":
            expect_head = rest[i + 1] if i + 1 < len(rest) else None
            i += 2
            continue
        positional.append(rest[i])
        i += 1
    if len(positional) != 1 or expect_head == "":
        print(__doc__, file=sys.stderr)
        return 2
    args = positional

    prev = None
    count = 0
    with open(args[0], encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            recomputed = compute_event_hash(event)
            if recomputed != event["event_hash"]:
                print(
                    f"FAILED at line {lineno} (event {event.get('event_id')}): "
                    f"stored hash {event['event_hash'][:16]}... != recomputed {recomputed[:16]}..."
                )
                return 1
            if prev is not None and event["prev_hash"] != prev:
                print(
                    f"FAILED at line {lineno} (event {event.get('event_id')}): "
                    f"prev_hash does not match previous event (chain broken)"
                )
                return 1
            prev = event["event_hash"]
            count += 1

    if expect_head is not None and prev != expect_head:
        print(f"FAILED: final hash {prev} != expected head {expect_head}")
        return 1

    print(f"OK: {count} events verified" + (", head matches" if expect_head else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
