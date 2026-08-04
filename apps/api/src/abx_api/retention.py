"""Delete expired payload bodies while preserving event hashes and metadata."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from abx_api.settings import settings
from abx_api.store import pg_pool, s3_client


def run_retention(now: datetime | None = None) -> int:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    with pg_pool().connection() as conn:
        tenants = conn.execute(
            "SELECT t.id,COALESCE(s.retention_days,30),s.updated_at FROM tenants t "
            "LEFT JOIN tenant_settings s ON s.tenant_id=t.id"
        ).fetchall()
    deleted = 0
    s3 = s3_client()
    for tenant_id, retention_days, policy_updated_at in tenants:
        cutoff = current - timedelta(days=int(retention_days))
        # When the payload was RECORDED, which is what a retention promise is
        # about. The object's LastModified is not that: storage tiering changes
        # an object's class with a same-key copy, and a copy resets
        # LastModified. Expiring by it meant a tiered batch survived its
        # retention window by exactly the tiering age - a tenant who asked for
        # 30 days and tiers at 10 kept payloads for 40.
        with pg_pool().connection() as conn:
            recorded_at = {
                str(key): value
                for key, value in conn.execute(
                    "SELECT object_key, created_at FROM payload_batches WHERE tenant_id=%s",
                    (tenant_id,),
                ).fetchall()
            }
        pages = s3.get_paginator("list_objects_v2").paginate(
            Bucket=settings.payload_bucket, Prefix=f"{tenant_id}/"
        )
        for page in pages:
            expired = []
            for item in page.get("Contents", []):
                # An object with no row is an orphan from a crashed write and
                # has no recorded time to appeal to, so it ages on the store's
                # clock. Tiering never touches an unreferenced object, so that
                # clock has not been reset.
                basis = recorded_at.get(item["Key"]) or item["LastModified"]
                if basis.tzinfo is None:
                    basis = basis.replace(tzinfo=UTC)
                if basis.astimezone(UTC) < cutoff:
                    expired.append({"Key": item["Key"]})
            if expired:
                # Recheck the policy under the tenant lock before each bounded
                # external delete. A concurrent settings change cancels this run.
                with pg_pool().connection() as conn, conn.transaction():
                    tenant = conn.execute(
                        "SELECT id FROM tenants WHERE id=%s FOR UPDATE",
                        (tenant_id,),
                    ).fetchone()
                    current_policy = conn.execute(
                        "SELECT retention_days,updated_at FROM tenant_settings "
                        "WHERE tenant_id=%s",
                        (tenant_id,),
                    ).fetchone()
                    expected = (int(retention_days), policy_updated_at)
                    actual = (
                        (int(current_policy[0]), current_policy[1])
                        if current_policy
                        else (30, None)
                    )
                    if tenant is None or actual != expected:
                        break
                    s3.delete_objects(
                        Bucket=settings.payload_bucket,
                        Delete={"Objects": expired, "Quiet": True},
                    )
                    # Batch objects carry many payloads; drop their index rows
                    # too. The cascade to payload_segments destroys the wrapped
                    # data keys, so an expired batch is unreadable even if a
                    # copy of the object survives in a backup or old version.
                    conn.execute(
                        "DELETE FROM payload_batches WHERE tenant_id=%s "
                        "AND object_key = ANY(%s)",
                        (tenant_id, [item["Key"] for item in expired]),
                    )
                    deleted += len(expired)
    return deleted


def main() -> int:
    print(f"deleted {run_retention()} expired payload bodies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
