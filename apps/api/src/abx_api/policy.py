"""Runtime policy plane: management and decisions (plan2 phase 25).

Separate from the recording plane by design. The tap consults this over the
network with a hard timeout and treats any failure as the tenant's configured
default, so this service being down degrades ENFORCEMENT and never recording.

Every decision, allow and deny alike, is recorded as a canonical event. A deny
that leaves no trace is indistinguishable from a bug in the agent, and an allow
that leaves no trace makes it impossible to answer "was this action considered
and permitted, or never evaluated at all".
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from abx_rules.policy import (
    VALID_ID,
    Decision,
    Effect,
    OnError,
    Policy,
    PolicyRequest,
    decide,
    on_evaluation_failure,
)
from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, StringConstraints

from abx_api.auth import IngestIdentity, ingest_identity_from_token
from abx_api.rbac import require_configure, require_read
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/policy")
logger = logging.getLogger(__name__)


class PolicyUpsert(BaseModel):
    policy_id: Annotated[str, StringConstraints(min_length=2, max_length=64)]
    effect: Effect
    description: str = Field(default="", max_length=500)
    enabled: bool = True
    on_error: OnError = OnError.ALLOW
    priority: int = Field(default=100, ge=0, le=10_000)
    match_destructive: bool = False
    match_operations: list[str] = Field(default_factory=list, max_length=64)
    match_tools: list[str] = Field(default_factory=list, max_length=64)
    match_resource_prefixes: list[str] = Field(default_factory=list, max_length=64)
    match_agents: list[str] = Field(default_factory=list, max_length=64)


class PolicyView(BaseModel):
    policy_id: str
    version: int
    effect: str
    enabled: bool
    on_error: str
    priority: int
    description: str
    created_at: str


class DecisionRequest(BaseModel):
    agent_id: str = Field(default="", max_length=256)
    operation: str = Field(default="", max_length=512)
    tool_name: str = Field(default="", max_length=256)
    resource_refs: list[str] = Field(default_factory=list, max_length=256)
    credential_ref: str | None = None


class DecisionView(BaseModel):
    effect: str
    allowed: bool
    policy_id: str | None
    policy_version: int | None
    reason: str
    degraded: bool
    enforcement_enabled: bool


def _load(conn: Any, tenant_id: str) -> list[Policy]:
    rows = conn.execute(
        "SELECT policy_id, version, effect, enabled, on_error, match_destructive, "
        "match_operations, match_tools, match_resource_prefixes, match_agents, "
        "description FROM policies "
        "WHERE tenant_id=%s AND superseded_at IS NULL ORDER BY priority, policy_id",
        (tenant_id,),
    ).fetchall()
    return [
        Policy(
            policy_id=str(row[0]), version=int(row[1]), effect=Effect(str(row[2])),
            enabled=bool(row[3]), on_error=OnError(str(row[4])),
            match_destructive=bool(row[5]),
            match_operations=tuple(row[6] or ()), match_tools=tuple(row[7] or ()),
            match_resource_prefixes=tuple(row[8] or ()), match_agents=tuple(row[9] or ()),
            description=str(row[10]),
        )
        for row in rows
    ]


@router.get("", response_model=list[PolicyView], dependencies=[Depends(require_read)])
def list_policies(tenant_id: str) -> list[PolicyView]:
    with pg_pool().connection() as conn:
        rows = conn.execute(
            "SELECT policy_id, version, effect, enabled, on_error, priority, "
            "description, created_at FROM policies "
            "WHERE tenant_id=%s AND superseded_at IS NULL ORDER BY priority, policy_id",
            (tenant_id,),
        ).fetchall()
    return [
        PolicyView(
            policy_id=str(row[0]), version=int(row[1]), effect=str(row[2]),
            enabled=bool(row[3]), on_error=str(row[4]), priority=int(row[5]),
            description=str(row[6]), created_at=row[7].isoformat(),
        )
        for row in rows
    ]


@router.put("", response_model=PolicyView, dependencies=[Depends(require_configure)])
def upsert_policy(tenant_id: str, request: PolicyUpsert) -> PolicyView:
    """Write a NEW VERSION rather than overwriting.

    A customer must be able to prove which policy was in force at any past
    moment, so history is retained the same way the event log retains events.
    """
    if not VALID_ID.fullmatch(request.policy_id):
        raise HTTPException(
            status_code=422,
            detail="policy_id must be lowercase alphanumeric with dashes",
        )
    candidate = Policy(
        policy_id=request.policy_id, version=1, effect=request.effect,
        enabled=request.enabled, on_error=request.on_error,
        match_destructive=request.match_destructive,
        match_operations=tuple(request.match_operations),
        match_tools=tuple(request.match_tools),
        match_resource_prefixes=tuple(request.match_resource_prefixes),
        match_agents=tuple(request.match_agents),
    )
    if candidate.is_empty:
        # A policy matching nothing is almost always a half-written deny.
        raise HTTPException(
            status_code=422,
            detail="a policy must declare at least one match condition",
        )

    with pg_pool().connection() as conn:
        previous = conn.execute(
            "SELECT max(version) FROM policies WHERE tenant_id=%s AND policy_id=%s",
            (tenant_id, request.policy_id),
        ).fetchone()
        version = int(previous[0]) + 1 if previous and previous[0] else 1
        conn.execute(
            "UPDATE policies SET superseded_at=now() "
            "WHERE tenant_id=%s AND policy_id=%s AND superseded_at IS NULL",
            (tenant_id, request.policy_id),
        )
        row = conn.execute(
            "INSERT INTO policies (tenant_id, policy_id, version, effect, enabled, "
            "on_error, priority, match_destructive, match_operations, match_tools, "
            "match_resource_prefixes, match_agents, description) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING created_at",
            (
                tenant_id, request.policy_id, version, str(request.effect),
                request.enabled, str(request.on_error), request.priority,
                request.match_destructive, request.match_operations,
                request.match_tools, request.match_resource_prefixes,
                request.match_agents, request.description,
            ),
        ).fetchone()
    assert row is not None

    # Any write re-opens the question of whether this tenant is fail-closed.
    # Dropping rather than recomputing keeps the bias toward allow: the next
    # successful evaluation re-learns it, and until then a policy that was just
    # turned off cannot keep denying from a stale entry.
    _FAIL_CLOSED_SEEN.pop(tenant_id, None)

    from abx_api.admin_audit import record_admin_action

    record_admin_action(
        tenant_id, "policy updated", request.policy_id,
        {"version": version, "effect": str(request.effect),
         "on_error": str(request.on_error), "enabled": request.enabled},
    )
    return PolicyView(
        policy_id=request.policy_id, version=version, effect=str(request.effect),
        enabled=request.enabled, on_error=str(request.on_error),
        priority=request.priority, description=request.description,
        created_at=row[0].isoformat(),
    )


@router.post("/decide", response_model=DecisionView)
def decide_action(
    request: DecisionRequest,
    identity: Annotated[IngestIdentity, Depends(ingest_identity_from_token)],
) -> DecisionView:
    """Evaluate one action. Never raises: a failure here is a decision, not a 500.

    Authenticated by the WRITE-ONLY INGEST TOKEN, not a read token, because every
    call appends a decision event to the tamper-evident chain. The recording
    plane is fed only by write-only ingest tokens (blueprint 6); a read-scoped
    principal able to append here could inject attacker-shaped records into the
    evidence store that `/v1/chain/verify` and the compliance exports attest to.

    Taking the tenant from the token rather than a query parameter is the same
    rule that governs ingest: a caller must not be able to name the tenant it
    writes into.
    """
    tenant_id = identity.tenant_id
    enforcement = False
    policies: list[Policy] = []
    decision: Decision
    try:
        with pg_pool().connection() as conn:
            setting = conn.execute(
                "SELECT policy_enforcement FROM tenant_settings WHERE tenant_id=%s",
                (tenant_id,),
            ).fetchone()
            enforcement = bool(setting[0]) if setting else False
            policies = _load(conn, tenant_id)
        _remember_fail_closed(tenant_id, policies, enforcement)
    except Exception as exc:
        logger.exception("policy evaluation failed for tenant %s", tenant_id)
        decision = _degraded_decision(tenant_id, str(exc))
        _record(tenant_id, request, decision, enforcement)
        return _view(decision, enforcement)

    # decide() is inside the guard too. It is pure today, but this endpoint sits
    # in the agent's request path, and the promise is that a failure here is a
    # decision rather than a 500 - a promise that only holds if the evaluation
    # itself is covered, not just the load before it.
    try:
        decision = decide(policies, _request_of(request))
        if not enforcement:
            # Evaluated and recorded, but advisory: a tenant that has not opted
            # in sees what a policy WOULD have done without anything blocked.
            decision = Decision(
                Effect.ALLOW, decision.policy_id, decision.policy_version,
                f"enforcement is disabled for this tenant (would have been "
                f"{decision.effect.value}: {decision.reason})",
                evaluated=decision.evaluated,
            )
    except Exception as exc:
        logger.exception("policy evaluation raised for tenant %s", tenant_id)
        decision = on_evaluation_failure(policies, str(exc))

    _record(tenant_id, request, decision, enforcement)
    return _view(decision, enforcement)


#: Tenants last observed with an enabled, enforced, fail-closed policy.
#:
#: `on_evaluation_failure` picks the fail-closed policies out of the list it is
#: given, and that list comes from the policy store. So in the one failure the
#: opt-in exists for - the store being unreachable - the list is empty and a
#: tenant who asked to be denied gets allowed instead. The opt-in lived in the
#: thing that died.
#:
#: Remembering it per process closes that. Two deliberate biases, both toward
#: allow, because the product's failure mode is "the agent keeps working":
#:
#:   - a process that has never successfully evaluated for a tenant has not
#:     learned their opt-in and allows; and
#:   - any policy write drops the entry, so a fail-closed policy that was just
#:     disabled cannot keep denying from cache. Turning a policy off must never
#:     make the system stricter.
_FAIL_CLOSED_SEEN: dict[str, tuple[str, int]] = {}


def _remember_fail_closed(
    tenant_id: str, policies: list[Policy], enforcement: bool
) -> None:
    closed = next(
        (p for p in policies if p.enabled and p.on_error is OnError.DENY), None
    )
    if enforcement and closed is not None:
        _FAIL_CLOSED_SEEN[tenant_id] = (closed.policy_id, closed.version)
    else:
        _FAIL_CLOSED_SEEN.pop(tenant_id, None)


def _degraded_decision(tenant_id: str, detail: str) -> Decision:
    """The decision when the policy store itself could not be reached."""
    remembered = _FAIL_CLOSED_SEEN.get(tenant_id)
    if remembered is None:
        return on_evaluation_failure([], detail)
    policy_id, version = remembered
    return Decision(
        Effect.DENY, policy_id, version,
        f"policy store unreachable and {policy_id} is fail-closed: {detail}",
        degraded=True,
    )


def _request_of(request: DecisionRequest) -> PolicyRequest:
    return PolicyRequest(
        operation=request.operation, tool_name=request.tool_name,
        resource_refs=tuple(request.resource_refs),
        credential_ref=request.credential_ref, agent_id=request.agent_id,
    )


def _view(decision: Decision, enforcement: bool) -> DecisionView:
    return DecisionView(
        effect=decision.effect.value, allowed=decision.allowed,
        policy_id=decision.policy_id, policy_version=decision.policy_version,
        reason=decision.reason, degraded=decision.degraded,
        enforcement_enabled=enforcement,
    )


def _record(
    tenant_id: str, request: DecisionRequest, decision: Decision, enforcement: bool
) -> None:
    """Chain the decision. Recording failure must not change the decision."""
    from abx_api.ingest import ingest_events

    refs = [f"abx:policy-decision:{decision.effect.value}"]
    if decision.policy_id:
        refs.append(f"abx:policy:{decision.policy_id}:v{decision.policy_version}")
    if decision.degraded:
        refs.append("abx:policy-degraded:true")
    if not enforcement:
        refs.append("abx:policy-advisory:true")

    event = IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": request.agent_id or "abx-policy",
        "session_id": f"policy:{uuid.uuid4()}", "seq": 0,
        "ts": datetime.now(UTC), "source": "admin_api", "event_type": "agent_step",
        "operation": {
            "name": f"policy decision {decision.effect.value}",
            "provider": "leaflyst",
            "target": request.operation or request.tool_name or "unknown",
            "outcome": "denied" if decision.effect is Effect.DENY else "success",
            "duration_ms": 0,
        },
        "resource_refs": refs,
        "payload": json.dumps({
            "reason": decision.reason,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "degraded": decision.degraded,
            "enforcement_enabled": enforcement,
            "evaluated": list(decision.evaluated),
        }),
    })
    try:
        ingest_events(tenant_id, [event])
    except Exception:
        logger.exception("policy decision was not chained for tenant %s", tenant_id)
