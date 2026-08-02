"""Runtime policy decisions (plan2 phase 25, blueprint2 19).

Deliberately a SEPARATE PLANE from recording, and the reason is the product's
core invariant rather than tidiness. The recording failure mode is "agent keeps
working, recording degrades". A blocking path inverts that by construction: a
plane that can deny an action can also fail and stop the agent. So:

- policy evaluation never runs in the tap's process;
- evaluation failure resolves to the tenant's configured default, and the
  default default is ALLOW;
- fail-closed exists but must be chosen explicitly, per policy, by the customer.
  A product that silently fails closed will eventually take down a customer's
  production and be right about it, which is not a defence anyone accepts.

Matching reuses the rule vocabulary rather than inventing a second one: the
destructive lexicon here is the same object rule 1 fires on, so "what the
product warns about" and "what the product can block" cannot drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from abx_rules.engine import DESTRUCTIVE


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class OnError(StrEnum):
    """What a policy does when evaluation itself fails."""

    ALLOW = "allow"  # default: an outage of ours must not become an outage of theirs
    DENY = "deny"  # opt-in, per policy, by explicit customer choice


@dataclass(frozen=True)
class PolicyRequest:
    """The action a policy is being asked about."""

    operation: str = ""
    tool_name: str = ""
    resource_refs: tuple[str, ...] = ()
    credential_ref: str | None = None
    agent_id: str = ""


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    effect: Effect
    enabled: bool = True
    on_error: OnError = OnError.ALLOW
    # All conditions present must match. An empty policy matches nothing, so a
    # half-written policy cannot accidentally deny everything.
    match_destructive: bool = False
    match_operations: tuple[str, ...] = ()
    match_tools: tuple[str, ...] = ()
    match_resource_prefixes: tuple[str, ...] = ()
    match_agents: tuple[str, ...] = ()
    description: str = ""

    @property
    def is_empty(self) -> bool:
        return not (
            self.match_destructive
            or self.match_operations
            or self.match_tools
            or self.match_resource_prefixes
            or self.match_agents
        )

    def matches(self, request: PolicyRequest) -> bool:
        if not self.enabled or self.is_empty:
            return False
        if self.match_destructive and not DESTRUCTIVE.search(request.operation):
            return False
        if self.match_operations and not any(
            _glob(pattern, request.operation) for pattern in self.match_operations
        ):
            return False
        if self.match_tools and request.tool_name not in self.match_tools:
            return False
        if self.match_agents and request.agent_id not in self.match_agents:
            return False
        return not self.match_resource_prefixes or any(
            ref.startswith(prefix)
            for prefix in self.match_resource_prefixes
            for ref in request.resource_refs
        )


@dataclass(frozen=True)
class Decision:
    effect: Effect
    policy_id: str | None
    policy_version: int | None
    reason: str
    # True when the decision came from a failure path rather than a match.
    degraded: bool = False
    evaluated: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW


def _glob(pattern: str, value: str) -> bool:
    """Trailing-* prefix match, so `tools/call *` is expressible.

    Deliberately not a full glob: a policy language an operator cannot predict
    at 3am is worse than one that is slightly under-powered.
    """
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def decide(policies: list[Policy], request: PolicyRequest) -> Decision:
    """Evaluate a request against an ordered policy set.

    First matching DENY wins; an explicit ALLOW short-circuits any later deny,
    which is what makes a narrow exemption expressible. No match is an allow,
    so policy is opt-in per action rather than a default-deny posture the
    customer did not ask for.
    """
    matched: list[str] = []
    for policy in policies:
        if not policy.matches(request):
            continue
        matched.append(policy.policy_id)
        if policy.effect is Effect.ALLOW:
            return Decision(
                Effect.ALLOW, policy.policy_id, policy.version,
                f"explicitly allowed by {policy.policy_id}",
                evaluated=tuple(matched),
            )
        return Decision(
            Effect.DENY, policy.policy_id, policy.version,
            policy.description or f"denied by {policy.policy_id}",
            evaluated=tuple(matched),
        )
    return Decision(
        Effect.ALLOW, None, None, "no policy matched this action",
        evaluated=tuple(matched),
    )


def on_evaluation_failure(policies: list[Policy], detail: str) -> Decision:
    """The decision when evaluation could not be completed.

    Fail-closed only if a policy explicitly opted in. Anything else allows, and
    the decision is marked degraded so the record shows the product could not
    evaluate rather than implying it approved.
    """
    closed = [p for p in policies if p.enabled and p.on_error is OnError.DENY]
    if closed:
        return Decision(
            Effect.DENY, closed[0].policy_id, closed[0].version,
            f"policy evaluation failed and {closed[0].policy_id} is fail-closed: {detail}",
            degraded=True,
        )
    return Decision(
        Effect.ALLOW, None, None,
        f"policy evaluation failed and no policy is fail-closed: {detail}",
        degraded=True,
    )


VALID_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
