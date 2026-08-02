"""Master-key rotation: re-wrap and the startup readability guard.

Rotation is a two-step operation an operator controls:

1. Promote a new key to active and move the old one to the retired list. New
   payloads seal under the new key immediately; old ones stay readable.
2. Run the re-wrap job until no segment references the retired key, then drop
   it from configuration.

Re-wrapping touches only the wrapped data key, never the payload object, so it
costs no object rewrite and cannot corrupt payload bytes. The plaintext data
key exists only in memory and is never persisted or logged.

The guard exists because the failure it prevents is silent and unrecoverable:
removing a key that segments still reference makes those payloads permanently
unreadable, and without the check the first symptom would be a failed evidence
read during an incident. Failing at startup turns that into an operator error
before traffic, which is the whole point.
"""

from __future__ import annotations

from dataclasses import dataclass

from abx_api.payload_crypto import keyring, rewrap
from abx_api.store import pg_pool

BATCH_SIZE = 500


@dataclass(frozen=True)
class KeyUsage:
    master_key_id: str
    segments: int
    known: bool


def key_usage() -> list[KeyUsage]:
    """Which master keys segments actually reference, and whether we hold them."""
    ring = keyring()
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT master_key_id, count(*) FROM payload_segments "
            "GROUP BY master_key_id ORDER BY master_key_id"
        ).fetchall()
    return [
        KeyUsage(str(row[0]), int(row[1]), str(row[0]) in ring.keys) for row in rows
    ]


def unreadable_segments() -> list[KeyUsage]:
    return [usage for usage in key_usage() if not usage.known]


def assert_keyring_covers_stored_payloads() -> None:
    """Fail closed at startup when a referenced master key is missing.

    Per-request failure would surface as sporadic unreadable evidence, which is
    exactly when it must not surface.
    """
    missing = unreadable_segments()
    if not missing:
        return
    detail = ", ".join(f"{usage.master_key_id} ({usage.segments} segments)" for usage in missing)
    raise RuntimeError(
        "payload segments reference master keys that are not configured: "
        f"{detail}. Restore them to ABX_PAYLOAD_RETIRED_KEYS, or those payloads "
        "are permanently unreadable."
    )


def rewrap_pending(limit: int = BATCH_SIZE) -> int:
    """Re-wrap up to `limit` segments still using a retired key.

    Returns how many were moved. Each segment commits on its own so an
    interrupted run leaves a consistent mix of old and new wrapping rather than
    a half-written batch; both are readable while their key is configured.
    """
    ring = keyring()
    if not ring.retired_ids:
        return 0

    moved = 0
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT payload_ref, wrapped_key, key_nonce, master_key_id "
            "FROM payload_segments WHERE master_key_id = ANY(%s) LIMIT %s",
            (ring.retired_ids, limit),
        ).fetchall()
        for payload_ref, wrapped_key, key_nonce, master_key_id in rows:
            wrapped, nonce, active_id = rewrap(
                bytes(wrapped_key), bytes(key_nonce), str(master_key_id)
            )
            # Guarded on the old key id: if erasure deleted the row, or another
            # worker already moved it, this updates nothing rather than
            # resurrecting or double-wrapping it.
            moved += conn.execute(
                "UPDATE payload_segments SET wrapped_key=%s, key_nonce=%s, "
                "master_key_id=%s WHERE payload_ref=%s AND master_key_id=%s",
                (wrapped, nonce, active_id, payload_ref, str(master_key_id)),
            ).rowcount
    return moved


def rewrap_all() -> int:
    """Drain every retired-key segment. Returns the total re-wrapped."""
    total = 0
    while (moved := rewrap_pending()) > 0:
        total += moved
    return total


def main() -> None:
    ring = keyring()
    if not ring.retired_ids:
        print(f"active key {ring.active_id}; no retired keys configured")
        return
    total = rewrap_all()
    remaining = [usage for usage in key_usage() if usage.master_key_id != ring.active_id]
    print(f"re-wrapped {total} segments onto {ring.active_id}")
    if remaining:
        for usage in remaining:
            print(f"still on {usage.master_key_id}: {usage.segments} segments")
    else:
        print("no segments reference a retired key; it is safe to drop from config")


if __name__ == "__main__":
    main()
