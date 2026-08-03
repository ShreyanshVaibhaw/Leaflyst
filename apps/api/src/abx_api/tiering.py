"""Age-based payload storage tiering (blueprint2, plan2 phase 22).

Batch packing from phase 14 makes this cheap: many payloads already share one
object, so tiering moves the OBJECT and leaves every `payload_segments` row
untouched. Byte offsets, wrapped keys, and erasure semantics are all unchanged
by a storage-class transition.

One hard constraint shapes the design. Replay and evidence export must be able
to read any retained payload IMMEDIATELY - an incident responder cannot wait
hours for a restore, and an auditor verifying an evidence pack certainly
cannot. So tiering targets only storage classes that remain directly readable
(the infrequent-access family). Archive classes such as GLACIER and DEEP_ARCHIVE
would cut cost further and are deliberately NOT offered: they make an object
unreadable until restored, which would turn a retained payload into one that
exists on paper but cannot be produced on demand.

Tiering never changes what is retained. Retention still deletes the object and
cascades the wrapped keys away; this only changes what the bytes cost while
they are still being kept.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from abx_api.settings import settings
from abx_api.store import pg_pool, s3_client

# Storage classes that stay immediately readable. Anything requiring a restore
# is excluded on purpose; see the module docstring.
READABLE_COLD_CLASSES = frozenset({"STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING"})
DEFAULT_COLD_CLASS = "STANDARD_IA"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TieringResult:
    scanned: int
    transitioned: int
    bytes_moved: int
    skipped_recent: int
    # Objects the store refused to transition. Counted and logged rather than
    # swallowed: a cost job that quietly does nothing looks identical to one
    # that is working, and the bill is the only thing that would ever notice.
    # Not every S3-compatible store supports the infrequent-access classes -
    # MinIO, used by the dev stack, rejects them outright.
    failed: int = 0


class TierClassError(ValueError):
    """The configured cold storage class would not be immediately readable."""


def cold_storage_class() -> str:
    value = (settings.payload_cold_storage_class or DEFAULT_COLD_CLASS).strip().upper()
    if value not in READABLE_COLD_CLASSES:
        raise TierClassError(
            f"ABX_PAYLOAD_COLD_STORAGE_CLASS '{value}' is not immediately readable. "
            f"Allowed: {', '.join(sorted(READABLE_COLD_CLASSES))}. Archive classes "
            "would make a retained payload unproducible without a restore."
        )
    return value


def run_tiering(now: datetime | None = None, limit: int = 1000) -> TieringResult:
    """Move batch objects older than the tiering age to a colder class.

    Driven from `payload_batches` rather than by listing the bucket: the table
    is the authority on which objects are still referenced, so an unreferenced
    object left by a crashed write is never touched here - retention sweeps it.
    """
    target_class = cold_storage_class()
    current = (now or datetime.now(UTC)).astimezone(UTC)
    scanned = transitioned = bytes_moved = skipped = failed = 0
    s3 = s3_client()

    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT b.id, b.object_key, b.byte_size, b.created_at, b.tenant_id, "
            "COALESCE(s.payload_tier_days, 0) "
            "FROM payload_batches b "
            "LEFT JOIN tenant_settings s ON s.tenant_id = b.tenant_id "
            "WHERE b.tiered_at IS NULL ORDER BY b.created_at LIMIT %s",
            (limit,),
        ).fetchall()

    for batch_id, object_key, byte_size, created_at, _tenant_id, tier_days in rows:
        scanned += 1
        if int(tier_days) < 1:
            continue  # tiering disabled for this tenant
        created = created_at if created_at.tzinfo else created_at.replace(tzinfo=UTC)
        if created > current - timedelta(days=int(tier_days)):
            skipped += 1
            continue
        try:
            # A same-key copy is how S3 changes storage class in place. The
            # bytes are identical, so segment offsets stay valid.
            s3.copy_object(
                Bucket=settings.payload_bucket,
                Key=object_key,
                CopySource={"Bucket": settings.payload_bucket, "Key": object_key},
                StorageClass=target_class,
                MetadataDirective="COPY",
            )
        except Exception:
            # The payload is untouched and still readable; only the saving is
            # lost. Surfaced so a store that refuses the class is visible
            # instead of showing up as an unexplained bill months later.
            logger.warning(
                "storage tiering to %s refused for %s", target_class, object_key,
                exc_info=True,
            )
            failed += 1
            continue
        with pg_pool().connection() as conn:
            conn.execute(
                "UPDATE payload_batches SET tiered_at = now(), storage_class = %s "
                "WHERE id = %s",
                (target_class, batch_id),
            )
        transitioned += 1
        bytes_moved += int(byte_size or 0)

    return TieringResult(scanned, transitioned, bytes_moved, skipped, failed)


def main() -> int:
    result = run_tiering()
    print(
        f"tiering: scanned {result.scanned}, transitioned {result.transitioned} "
        f"({result.bytes_moved} bytes), {result.skipped_recent} still hot, "
        f"{result.failed} refused by the store"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
