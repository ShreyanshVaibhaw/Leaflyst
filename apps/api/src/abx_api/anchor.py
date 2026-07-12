"""Daily chain-anchor job (blueprint 4.1): copy every tenant's chain head into
the object-locked, versioned anchor bucket. Run daily (cron / scheduler).

    uv run python -m abx_api.anchor
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from abx_api.settings import settings
from abx_api.store import ensure_buckets, pg_pool, s3_client


def anchor_all() -> int:
    ensure_buckets()
    now = datetime.now(UTC)
    with pg_pool().connection() as conn:
        heads = conn.execute(
            "SELECT tenant_id, head_hash, head_seq FROM chain_heads"
        ).fetchall()
    for tenant_id, head_hash, head_seq in heads:
        key = f"{tenant_id}/{now:%Y-%m-%d}.json"
        body = json.dumps(
            {
                "tenant_id": str(tenant_id),
                "head_hash": head_hash,
                "head_seq": int(head_seq),
                "anchored_at": now.isoformat(timespec="milliseconds"),
            }
        ).encode()
        encryption = (
            {"ServerSideEncryption": settings.s3_server_side_encryption}
            if settings.s3_server_side_encryption
            else {}
        )
        s3_client().put_object(
            Bucket=settings.anchor_bucket, Key=key, Body=body, **encryption
        )
    return len(heads)


if __name__ == "__main__":
    print(f"anchored {anchor_all()} chain heads")
