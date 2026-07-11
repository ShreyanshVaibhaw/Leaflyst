"""GET /v1/chain/verify - recompute and check a tenant's hash chain.

Walks events in chain order (chain_seq), recomputes every event_hash, checks
prev_hash continuity, and - when the range reaches the head - compares against
the checkpointed chain head. Payload bodies are NOT needed: digests are part
of the hashed event, so deleted payloads do not break verification.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from abx_api.auth import require_admin
from abx_api.chain import row_to_event, verify_chain
from abx_api.store import ch_client, pg_pool

router = APIRouter()


class VerifyResult(BaseModel):
    valid: bool
    events_checked: int
    first_divergent_event_id: str | None = None
    head_matches_checkpoint: bool | None = None


@router.get(
    "/v1/chain/verify", response_model=VerifyResult, dependencies=[Depends(require_admin)]
)
def verify(
    tenant_id: str,
    from_chain_seq: Annotated[int, "start of range"] = 1,
    to_chain_seq: int | None = None,
) -> VerifyResult:
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
    )
