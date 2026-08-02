"""GET /v1/chain/verify - recompute and check a tenant's hash chain.

Walks events in chain order (chain_seq), recomputes every event_hash, checks
prev_hash continuity, and - when the range reaches the head - compares against
the checkpointed chain head. Payload bodies are NOT needed: digests are part
of the hashed event, so deleted payloads do not break verification.
"""

from __future__ import annotations

import json
from typing import Annotated, Literal, TypedDict

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from abx_api.chain import GENESIS_HASH, row_to_event, verify_chain
from abx_api.rbac import require_read
from abx_api.settings import settings
from abx_api.store import ch_client, pg_pool, s3_client

router = APIRouter()


class AnchorRecord(TypedDict):
    ref: str
    tenant_id: str
    head_hash: str
    head_seq: int
    anchored_at: str


class VerifyResult(BaseModel):
    valid: bool
    events_checked: int
    first_divergent_event_id: str | None = None
    head_matches_checkpoint: bool | None = None
    verification_mode: Literal["full", "range", "anchored_suffix", "anchor_failed"] = "full"
    anchor_ref: str | None = None
    anchor_head_seq: int | None = None


@router.get(
    "/v1/chain/verify", response_model=VerifyResult, dependencies=[Depends(require_read)]
)
def verify(
    tenant_id: str,
    from_chain_seq: Annotated[int, "start of range"] = 1,
    to_chain_seq: int | None = None,
) -> VerifyResult:
    return verify_tenant_chain(tenant_id, from_chain_seq, to_chain_seq)


def verify_tenant_chain(
    tenant_id: str, from_chain_seq: int = 1, to_chain_seq: int | None = None
) -> VerifyResult:
    if from_chain_seq == 1 and to_chain_seq is None:
        anchored = _verify_from_latest_anchor(tenant_id)
        if anchored is not None:
            return anchored

    where = "tenant_id = %(t)s AND chain_seq >= %(lo)s"
    params: dict[str, object] = {"t": tenant_id, "lo": from_chain_seq}
    if to_chain_seq is not None:
        where += " AND chain_seq <= %(hi)s"
        params["hi"] = to_chain_seq

    result = ch_client().query(
        f"SELECT * FROM events WHERE {where} ORDER BY chain_seq",  # noqa: S608
        parameters=params,
    )
    rows = [dict(zip(result.column_names, r, strict=True)) for r in result.result_rows]
    events = [row_to_event(r) for r in rows]
    valid, divergent = verify_chain(events)
    if valid and events and from_chain_seq == 1 and events[0]["prev_hash"] != GENESIS_HASH:
        valid = False
        divergent = str(events[0]["event_id"])

    head_matches: bool | None = None
    if valid and events:
        with pg_pool().connection() as conn:
            head = conn.execute(
                "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id = %s",
                (tenant_id,),
            ).fetchone()
        if head is not None and int(head[1]) == rows[-1]["chain_seq"]:
            head_matches = events[-1]["event_hash"] == str(head[0])
            valid = valid and head_matches

    return VerifyResult(
        valid=valid,
        events_checked=len(events),
        first_divergent_event_id=divergent,
        head_matches_checkpoint=head_matches,
        verification_mode="range" if from_chain_seq != 1 or to_chain_seq is not None else "full",
    )


def _verify_from_latest_anchor(tenant_id: str) -> VerifyResult | None:
    with pg_pool().connection() as conn:
        head = conn.execute(
            "SELECT head_hash, head_seq FROM chain_heads WHERE tenant_id = %s",
            (tenant_id,),
        ).fetchone()
    if head is None or int(head[1]) < 1:
        return None

    head_hash = str(head[0])
    head_seq = int(head[1])
    anchor = _latest_anchor(tenant_id)
    if anchor is None:
        return None

    anchor_ref = str(anchor["ref"])
    anchor_seq = int(anchor["head_seq"])
    if anchor_seq < 1 or anchor_seq > head_seq:
        return VerifyResult(
            valid=False,
            events_checked=0,
            head_matches_checkpoint=False,
            verification_mode="anchor_failed",
            anchor_ref=anchor_ref,
            anchor_head_seq=anchor_seq,
        )

    checkpoint = ch_client().query(
        "SELECT event_id,event_hash FROM events WHERE tenant_id=%(tenant)s "
        "AND chain_seq=%(seq)s LIMIT 1",
        parameters={"tenant": tenant_id, "seq": anchor_seq},
    ).result_rows
    if not checkpoint:
        return VerifyResult(
            valid=False,
            events_checked=0,
            head_matches_checkpoint=False,
            verification_mode="anchor_failed",
            anchor_ref=anchor_ref,
            anchor_head_seq=anchor_seq,
        )

    checkpoint_event_id = str(checkpoint[0][0])
    checkpoint_hash = _string(checkpoint[0][1])
    if checkpoint_hash != anchor["head_hash"]:
        return VerifyResult(
            valid=False,
            events_checked=1,
            first_divergent_event_id=checkpoint_event_id,
            head_matches_checkpoint=False,
            verification_mode="anchor_failed",
            anchor_ref=anchor_ref,
            anchor_head_seq=anchor_seq,
        )

    result = ch_client().query(
        "SELECT * FROM events WHERE tenant_id=%(tenant)s AND chain_seq>%(anchor_seq)s "
        "AND chain_seq<=%(head_seq)s ORDER BY chain_seq",
        parameters={"tenant": tenant_id, "anchor_seq": anchor_seq, "head_seq": head_seq},
    )
    rows = [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]
    events = [row_to_event(row) for row in rows]
    valid, divergent = verify_chain(events)
    if valid and events and events[0]["prev_hash"] != anchor["head_hash"]:
        valid = False
        divergent = str(events[0]["event_id"])
    if valid and head_seq > anchor_seq and (
        not rows or int(rows[-1]["chain_seq"]) != head_seq
    ):
        valid = False
    head_matches = (
        checkpoint_hash == head_hash if not events else events[-1]["event_hash"] == head_hash
    )
    valid = valid and head_matches
    return VerifyResult(
        valid=valid,
        events_checked=len(events) + 1,
        first_divergent_event_id=divergent,
        head_matches_checkpoint=head_matches,
        verification_mode="anchored_suffix",
        anchor_ref=anchor_ref,
        anchor_head_seq=anchor_seq,
    )


def _latest_anchor(tenant_id: str) -> AnchorRecord | None:
    try:
        pages = s3_client().get_paginator("list_objects_v2").paginate(
            Bucket=settings.anchor_bucket, Prefix=f"{tenant_id}/"
        )
        anchors: list[AnchorRecord] = []
        for page in pages:
            for item in page.get("Contents", []):
                key = str(item["Key"])
                body = s3_client().get_object(Bucket=settings.anchor_bucket, Key=key)[
                    "Body"
                ].read()
                parsed = json.loads(body)
                if str(parsed.get("tenant_id")) != tenant_id:
                    continue
                anchors.append(
                    {
                        "ref": f"s3://{settings.anchor_bucket}/{key}",
                        "tenant_id": str(parsed["tenant_id"]),
                        "head_hash": str(parsed["head_hash"]),
                        "head_seq": int(parsed["head_seq"]),
                        "anchored_at": str(parsed["anchored_at"]),
                    }
                )
        return (
            max(anchors, key=lambda value: (value["head_seq"], value["anchored_at"]))
            if anchors
            else None
        )
    except Exception:
        return None


def _string(value: object) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)
