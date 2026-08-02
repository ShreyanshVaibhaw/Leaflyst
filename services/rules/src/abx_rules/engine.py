"""Deterministic anomaly rules with explicit cold-start behavior.

Rules 1-5 are the v0.1 set. Rules 6-7 cover runtime supply-chain compromise
from dynamic tool composition, which OWASP ranks ASI04 in its 2026 Top 10 for
Agentic Applications:

6. Rug pull - a tool definition changes after it was approved and trusted.
7. Tool poisoning - a tool description carries instructions aimed at the model
   rather than the user.

Rule 8 is the behavioural baseline: what five hand-written rules cannot
express. It is per-tenant and statistical, never a cross-tenant learned model,
and stays silent until an agent has a baseline to depart from.

Every rule stays explainable: the evidence a rule emits has to let a
non-technical reader see why it fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from abx_rules.baseline import AgentBaseline, Observation
from abx_rules.baseline import evidence as baseline_evidence
from abx_rules.baseline import fires as baseline_fires
from abx_rules.baseline import score as baseline_score
from abx_rules.baseline import summary as baseline_summary

DESTRUCTIVE = re.compile(
    r"(?:^|[\s/_-])(delete|drop|destroy|rm|truncate|force[-_ ]?push)(?:$|[\s/_-])",
    re.IGNORECASE,
)

# Instruction-shaped content in a tool description. A description is
# documentation for a human choosing a tool; text that addresses the model,
# suppresses disclosure, or redirects behavior is not documentation.
# Each pattern is named so a finding can say which one matched and why.
POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override_instructions", re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|rules?)", re.IGNORECASE)),
    ("system_prompt_reference", re.compile(
        r"\b(?:system\s+prompt|developer\s+message)\b", re.IGNORECASE)),
    ("suppress_disclosure", re.compile(
        r"(?:do\s*n[o']?t|never)\s+(?:tell|mention|inform|reveal|disclose|show)\s+"
        r"(?:the\s+)?(?:user|human|anyone)", re.IGNORECASE)),
    ("model_directive", re.compile(
        r"(?:^|[.\n])\s*(?:you\s+must|you\s+should\s+always|always\s+call|"
        r"before\s+(?:using|calling)\s+this\s+tool,?\s+you)", re.IGNORECASE)),
    # Either order: "include the API key" and "the API key must be included".
    ("credential_solicitation", re.compile(
        r"\b(?:include|provide|pass|send|attach|read|append|supply)\b[^.\n]{0,40}"
        r"\b(?:api[_\s-]?key|secret|password|token|credential)s?\b"
        r"|\b(?:api[_\s-]?key|secret|password|token|credential)s?\b[^.\n]{0,40}"
        r"\b(?:include|provide|pass|send|attach|read|append|supply)\b",
        re.IGNORECASE)),
    ("exfiltration_directive", re.compile(
        r"\b(?:send|forward|post|upload|exfiltrate)\b[^.\n]{0,30}"
        r"\b(?:to\s+https?://|to\s+the\s+following|external)", re.IGNORECASE)),
    ("hidden_marker", re.compile(
        r"<\s*(?:important|system|secret|hidden|instructions?)\s*>", re.IGNORECASE)),
)


def poison_matches(description: str) -> list[str]:
    """Names of the instruction-shaped patterns present in a description.

    Pure text analysis. The description is untrusted recorded content and is
    never executed, evaluated, or interpreted - only matched and reported.
    """
    if not description:
        return []
    return [name for name, pattern in POISON_PATTERNS if pattern.search(description)]


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
    # Rule 6: tools whose definition changed after first approval, as
    # (tool_name, days_trusted, sessions_trusted).
    changed_tools: tuple[tuple[str, float, int], ...] = ()
    # Rule 7: (tool_name, matched pattern names) for descriptions carrying
    # model-directed instructions.
    poisoned_tools: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # Rule 8: what this agent normally does, and what it just did. None means
    # no baseline was computed, which is not the same as an empty baseline.
    baseline: AgentBaseline | None = None
    observation: Observation | None = None


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
    alerts.extend(_tool_integrity(facts))
    alerts.extend(_behavioral(facts))
    return alerts


def _tool_integrity(facts: EventFacts) -> list[AlertCandidate]:
    """Rules 6 and 7: runtime supply-chain compromise (OWASP ASI04)."""
    alerts: list[AlertCandidate] = []
    for name, days_trusted, sessions in facts.changed_tools:
        # The longer a tool was trusted and the more it was used, the worse a
        # silent redefinition is: that trust window is the whole attack. A
        # first-session change is just a server publishing its tools.
        severity = "critical" if days_trusted >= 1 or sessions >= 3 else "high"
        alerts.append(AlertCandidate(
            "tool_rug_pull", severity,
            f"Tool '{name}' was redefined after being trusted",
            {
                "tool": name,
                "days_trusted": round(days_trusted, 2),
                "sessions_trusted": sessions,
                "why": (
                    f"'{name}' was approved and used across {sessions} session(s) "
                    f"over {days_trusted:.1f} day(s), then its definition changed. "
                    "An approved tool changing after the fact is the shape of a "
                    "rug pull; compare the definitions before using it again."
                ),
            },
        ))
    for name, patterns in facts.poisoned_tools:
        alerts.append(AlertCandidate(
            "tool_poisoning", "critical",
            f"Tool '{name}' description contains model-directed instructions",
            {
                "tool": name,
                "patterns": list(patterns),
                "why": (
                    f"The description for '{name}' reads as instructions to the "
                    "model rather than documentation for a person "
                    f"({', '.join(patterns)}). Tool descriptions are loaded into "
                    "model context, so this can steer tool choice and behavior."
                ),
            },
        ))
    return alerts


def _behavioral(facts: EventFacts) -> list[AlertCandidate]:
    """Rule 8: departure from this agent's own baseline.

    Silent during cold start by construction - `score` returns nothing until
    the baseline is established, so a new agent cannot be alerted on.
    """
    if facts.baseline is None or facts.observation is None:
        return []
    deviations = baseline_score(facts.baseline, facts.observation)
    if not baseline_fires(deviations):
        return []
    evidence = baseline_evidence(facts.baseline, facts.observation, deviations)
    evidence["why"] = (
        f"This agent departed from its own {facts.baseline.days_observed:.0f}-day "
        f"baseline: {baseline_summary(deviations)}."
    )
    dimensions = {deviation.dimension for deviation in deviations}
    return [AlertCandidate(
        "behavioral_deviation",
        # A credential the agent has never held is the one worth waking for.
        "critical" if "credential" in dimensions else "high",
        f"Agent {facts.agent_id} departed from its behavioural baseline",
        evidence,
    )]
