"""Per-agent behavioural baselines (plan2 phase 20).

Per-tenant statistical baselines, deliberately NOT cross-tenant learned models:
training on one customer's traffic to score another's raises a data-boundary
question this product's positioning cannot afford.

Two constraints inherited from blueprint 5.5 and non-negotiable:

- A mandatory cold-start silence per agent. A new install that sprays false
  positives is worse than one that says "learning".
- Every alert renders the baseline next to the observation. An unexplainable
  score is not shippable, because the product's credibility rests on a
  non-technical reader understanding the top finding without help.

Scoring is deliberately arithmetic rather than statistical machinery: an
incident responder has to be able to reconstruct why a number came out the way
it did, at 3am, from the evidence alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Cold start. Both must be satisfied before this rule can fire for an agent:
# elapsed time alone lets a weekend of silence look like a baseline, and
# session count alone lets a burst of activity in one hour look like a week.
MIN_BASELINE_DAYS = 7.0
MIN_BASELINE_SESSIONS = 5

# An hour is "unusual" when it holds less than this share of observed activity.
UNUSUAL_HOUR_SHARE = 0.01

# Weights. Ordered by how hard the thing is to explain away: a credential the
# agent has never used is a stronger signal than an unusual hour.
WEIGHT_UNSEEN_CREDENTIAL = 3
WEIGHT_UNSEEN_OPERATION = 2
WEIGHT_UNSEEN_RESOURCE_KIND = 2
WEIGHT_UNUSUAL_HOUR = 1

FIRE_AT_SCORE = 3


@dataclass(frozen=True)
class AgentBaseline:
    """What an agent has historically done, over a rolling window."""

    days_observed: float = 0.0
    sessions: int = 0
    operations: frozenset[str] = frozenset()
    resource_kinds: frozenset[str] = frozenset()
    credentials: frozenset[str] = frozenset()
    # Hour of day (UTC) -> events observed in it.
    hourly: dict[int, int] = field(default_factory=dict)

    @property
    def established(self) -> bool:
        return (
            self.days_observed >= MIN_BASELINE_DAYS
            and self.sessions >= MIN_BASELINE_SESSIONS
        )

    @property
    def total_events(self) -> int:
        return sum(self.hourly.values())

    def hour_share(self, hour: int) -> float:
        total = self.total_events
        return (self.hourly.get(hour, 0) / total) if total else 0.0


@dataclass(frozen=True)
class Observation:
    """The single event being scored against the baseline."""

    operation: str = ""
    resource_kinds: frozenset[str] = frozenset()
    credential_ref: str | None = None
    hour: int | None = None


@dataclass(frozen=True)
class Deviation:
    dimension: str
    observed: str
    weight: int
    explanation: str


def score(baseline: AgentBaseline, observation: Observation) -> list[Deviation]:
    """Which dimensions departed from the baseline, and by how much.

    Returns an empty list during cold start, so the caller cannot accidentally
    alert on an agent that has no baseline to depart from.
    """
    if not baseline.established:
        return []

    found: list[Deviation] = []

    if observation.credential_ref and observation.credential_ref not in baseline.credentials:
        found.append(Deviation(
            "credential", observation.credential_ref, WEIGHT_UNSEEN_CREDENTIAL,
            f"this agent has never used credential {observation.credential_ref} "
            f"in {baseline.days_observed:.0f} days of recorded activity",
        ))

    if observation.operation and observation.operation not in baseline.operations:
        found.append(Deviation(
            "operation", observation.operation, WEIGHT_UNSEEN_OPERATION,
            f"'{observation.operation}' is not among the "
            f"{len(baseline.operations)} operations this agent has performed before",
        ))

    for kind in sorted(observation.resource_kinds - baseline.resource_kinds):
        found.append(Deviation(
            "resource_kind", kind, WEIGHT_UNSEEN_RESOURCE_KIND,
            f"this agent has never touched a {kind} resource before",
        ))

    if observation.hour is not None:
        share = baseline.hour_share(observation.hour)
        if share < UNUSUAL_HOUR_SHARE:
            found.append(Deviation(
                "hour", f"{observation.hour:02d}:00 UTC", WEIGHT_UNUSUAL_HOUR,
                f"{share * 100:.1f}% of this agent's activity has happened in the "
                f"{observation.hour:02d}:00 UTC hour",
            ))

    return found


def total_score(deviations: list[Deviation]) -> int:
    return sum(deviation.weight for deviation in deviations)


def fires(deviations: list[Deviation]) -> bool:
    return total_score(deviations) >= FIRE_AT_SCORE


def evidence(
    baseline: AgentBaseline, observation: Observation, deviations: list[Deviation]
) -> dict[str, object]:
    """The baseline rendered next to the observation.

    This is the explainability requirement made concrete: a reviewer sees what
    is normal for this agent, what happened, and the arithmetic between them,
    without needing access to the underlying data.
    """
    return {
        "score": total_score(deviations),
        "fires_at": FIRE_AT_SCORE,
        "baseline": {
            "days_observed": round(baseline.days_observed, 1),
            "sessions": baseline.sessions,
            "distinct_operations": len(baseline.operations),
            "distinct_resource_kinds": len(baseline.resource_kinds),
            "credentials_used": sorted(baseline.credentials)[:10],
            "busiest_hours_utc": [
                hour for hour, _ in sorted(
                    baseline.hourly.items(), key=lambda item: -item[1]
                )[:3]
            ],
        },
        "observed": {
            "operation": observation.operation,
            "resource_kinds": sorted(observation.resource_kinds),
            "credential_ref": observation.credential_ref,
            "hour_utc": observation.hour,
        },
        "deviations": [
            {
                "dimension": deviation.dimension,
                "observed": deviation.observed,
                "weight": deviation.weight,
                "why": deviation.explanation,
            }
            for deviation in deviations
        ],
    }


def summary(deviations: list[Deviation]) -> str:
    """One sentence a non-technical reader can act on."""
    if not deviations:
        return "no departure from this agent's baseline"
    parts = [deviation.explanation for deviation in deviations]
    return "; ".join(parts)
