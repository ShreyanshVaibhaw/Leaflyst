"""Five deterministic anomaly rules with explicit cold-start behavior."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DESTRUCTIVE = re.compile(
    r"(?:^|[\s/_-])(delete|drop|destroy|rm|truncate|force[-_ ]?push)(?:$|[\s/_-])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EventFacts:
    event_id: str
    session_id: str
    agent_id: str
    operation: str
    credential_ref: str | None = None
    resource_refs: tuple[str, ...] = ()
    scanner_baseline: bool = False
    credential_flagged: bool = False
    outside_scanned_scope: bool = False
    history_days: float = 0
    session_event_count: int = 0
    trailing_session_median: float | None = None
    environment_crossover: bool = False
    tool_inventory_drift: bool = False


@dataclass(frozen=True)
class AlertCandidate:
    rule_id: str
    severity: str
    title: str
    evidence: dict[str, object] = field(default_factory=dict)


def evaluate(facts: EventFacts) -> list[AlertCandidate]:
    alerts: list[AlertCandidate] = []
    if DESTRUCTIVE.search(facts.operation):
        alerts.append(AlertCandidate(
            "destructive_operation", "critical", "First-time destructive operation",
            {"operation": facts.operation},
        ))
    if facts.scanner_baseline and (
        facts.credential_flagged or facts.outside_scanned_scope
    ):
        alerts.append(AlertCandidate(
            "credential_outside_scope", "critical",
            "Credential used outside scanned scope",
            {"credential_flagged": facts.credential_flagged,
             "outside_scanned_scope": facts.outside_scanned_scope,
             "resources": list(facts.resource_refs)},
        ))
    if (
        facts.history_days >= 7
        and facts.trailing_session_median is not None
        and facts.trailing_session_median > 0
        and facts.session_event_count > facts.trailing_session_median * 5
    ):
        alerts.append(AlertCandidate(
            "action_volume_spike", "high", "Action volume exceeds the 7-day baseline",
            {"session_events": facts.session_event_count,
             "trailing_median": facts.trailing_session_median},
        ))
    if facts.environment_crossover:
        alerts.append(AlertCandidate(
            "environment_crossover", "high", "Non-production agent touched production",
            {"resources": list(facts.resource_refs)},
        ))
    if facts.tool_inventory_drift:
        alerts.append(AlertCandidate(
            "tool_inventory_drift", "high", "MCP tool inventory changed",
            {"operation": facts.operation},
        ))
    return alerts
