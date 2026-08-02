"""Portable, anchored tenant-chain evidence for independent verification."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from abx_api.chain import row_to_event
from abx_api.rbac import require_export
from abx_api.settings import settings
from abx_api.store import ch_client, pg_pool, s3_client

router = APIRouter(prefix="/v1/evidence", dependencies=[Depends(require_export)])
PAGE_SIZE = 5_000


@router.get("/tenant")
def export_tenant_evidence(tenant_id: str) -> StreamingResponse:
    """Stream the complete tenant chain through its latest immutable anchor."""
    with pg_pool().connection() as conn:
        head = conn.execute(
            "SELECT head_hash,head_seq FROM chain_heads WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
    if head is None or int(head[1]) < 1:
        raise HTTPException(status_code=404, detail="tenant chain is empty")

    anchor = _latest_anchor(tenant_id)
    if anchor is None:
        raise HTTPException(status_code=409, detail="immutable chain anchor is unavailable")
    anchor_seq = int(anchor["head_seq"])
    if anchor_seq < 1 or anchor_seq > int(head[1]):
        raise HTTPException(status_code=409, detail="immutable chain anchor is invalid")

    last = ch_client().query(
        "SELECT event_hash FROM events WHERE tenant_id=%(tenant)s "
        "AND chain_seq=%(seq)s LIMIT 1",
        parameters={"tenant": tenant_id, "seq": anchor_seq},
    ).result_rows
    last_hash = _string(last[0][0]) if last else ""
    if last_hash != anchor["head_hash"]:
        raise HTTPException(status_code=503, detail="anchored chain snapshot is not available")

    checkpoint = {"head_hash": anchor["head_hash"], "head_seq": anchor_seq}
    exported_at = datetime.now(UTC).isoformat(timespec="milliseconds")
    response = StreamingResponse(
        _stream_bundle(tenant_id, exported_at, anchor_seq, checkpoint, anchor),
        media_type="application/x-ndjson",
    )
    response.headers["Content-Disposition"] = 'attachment; filename="tenant-evidence.ndjson"'
    response.headers["Cache-Control"] = "no-store"
    return response


def _stream_bundle(
    tenant_id: str,
    exported_at: str,
    head_seq: int,
    checkpoint: dict[str, Any],
    anchor: dict[str, Any],
) -> Iterator[bytes]:
    header = {
        "type": "header",
        "format": "abx-evidence-v1",
        "tenant_id": tenant_id,
        "exported_at": exported_at,
    }
    yield (json.dumps(header, separators=(",", ":")) + "\n").encode()
    next_seq = 1
    while next_seq <= head_seq:
        result = ch_client().query(
            "SELECT * FROM events WHERE tenant_id=%(tenant)s "
            "AND chain_seq>=%(start)s AND chain_seq<=%(head)s "
            "ORDER BY chain_seq LIMIT %(limit)s",
            parameters={
                "tenant": tenant_id,
                "start": next_seq,
                "head": head_seq,
                "limit": PAGE_SIZE,
            },
        )
        rows = [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]
        if not rows:
            raise RuntimeError("anchored chain changed during evidence export")
        for row in rows:
            chain_seq = int(row["chain_seq"])
            if chain_seq != next_seq:
                raise RuntimeError("anchored chain is not contiguous")
            item = {"type": "event", "chain_seq": chain_seq, "event": row_to_event(row)}
            yield (json.dumps(item, separators=(",", ":")) + "\n").encode()
            next_seq += 1
    footer = {"type": "footer", "checkpoint": checkpoint, "anchor": anchor}
    yield (json.dumps(footer, separators=(",", ":")) + "\n").encode()


def _latest_anchor(tenant_id: str) -> dict[str, Any] | None:
    try:
        pages = s3_client().get_paginator("list_objects_v2").paginate(
            Bucket=settings.anchor_bucket, Prefix=f"{tenant_id}/"
        )
        anchors: list[dict[str, Any]] = []
        for page in pages:
            for item in page.get("Contents", []):
                key = item["Key"]
                body = s3_client().get_object(
                    Bucket=settings.anchor_bucket, Key=key
                )["Body"].read()
                parsed = json.loads(body)
                if str(parsed.get("tenant_id")) != tenant_id:
                    continue
                anchors.append({
                    "ref": f"s3://{settings.anchor_bucket}/{key}",
                    "tenant_id": str(parsed["tenant_id"]),
                    "head_hash": str(parsed["head_hash"]),
                    "head_seq": int(parsed["head_seq"]),
                    "anchored_at": str(parsed["anchored_at"]),
                })
        return (
            max(anchors, key=lambda value: (value["head_seq"], value["anchored_at"]))
            if anchors
            else None
        )
    except Exception:
        return None


def _string(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)
