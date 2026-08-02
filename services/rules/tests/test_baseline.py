"""Rule 8: behavioural baselines.

The blueprint deferred this for insufficient data volume, so the rule's whole
job is to be honest about how much it knows. Two properties dominate:

- Cold start is enforced in `score`, not left to the caller. A new agent has
  no baseline to depart from, and a rule that sprays false positives on day
  one is worse than one that says "learning".
- Every alert carries the baseline next to the observation. An unexplainable
  score is not shippable, because the product's credibility rests on a
  non-technical reader understanding the top finding without help.
"""

from __future__ import annotations

from abx_rules import EventFacts, evaluate
from abx_rules.baseline import (
    MIN_BASELINE_DAYS,
    MIN_BASELINE_SESSIONS,
    AgentBaseline,
    Observation,
    evidence,
    fires,
    score,
)


def established(**overrides: object) -> AgentBaseline:
    base: dict[str, object] = {
        "days_observed": 30.0,
        "sessions": 40,
        "operations": frozenset({"tools/call echo", "tools/list"}),
        "resource_kinds": frozenset({"aws:s3", "file:/"}),
        "credentials": frozenset({"AKIAIOSFODNN7EXAMPLE"}),
        "hourly": {hour: 100 for hour in range(9, 18)},
    }
    base.update(overrides)
    return AgentBaseline(**base)  # type: ignore[arg-type]


def normal() -> Observation:
    return Observation(
        operation="tools/call echo",
        resource_kinds=frozenset({"aws:s3"}),
        credential_ref="AKIAIOSFODNN7EXAMPLE",
        hour=10,
    )


# -- cold start ---------------------------------------------------------------

def test_a_new_agent_is_never_scored() -> None:
    """Silence during cold start is enforced here so no caller can bypass it."""
    fresh = AgentBaseline(days_observed=0, sessions=0)
    wild = Observation(
        operation="delete everything",
        resource_kinds=frozenset({"aws:iam"}),
        credential_ref="brand-new",
        hour=3,
    )
    assert score(fresh, wild) == []
    assert not fires(score(fresh, wild))


def test_enough_days_but_too_few_sessions_stays_silent() -> None:
    """A burst of activity in one hour is not a week of behaviour."""
    thin = established(days_observed=MIN_BASELINE_DAYS + 1, sessions=MIN_BASELINE_SESSIONS - 1)
    assert not thin.established
    assert score(thin, Observation(operation="never seen", hour=3)) == []


def test_enough_sessions_but_too_few_days_stays_silent() -> None:
    """A weekend of silence is not a baseline either."""
    young = established(days_observed=MIN_BASELINE_DAYS - 1, sessions=MIN_BASELINE_SESSIONS + 10)
    assert not young.established
    assert score(young, Observation(operation="never seen", hour=3)) == []


def test_an_established_baseline_scores() -> None:
    assert established().established is True


# -- scoring ------------------------------------------------------------------

def test_normal_behaviour_scores_nothing() -> None:
    """The negative control. A rule that fires on ordinary traffic trains
    people to ignore it."""
    assert score(established(), normal()) == []


def test_an_unseen_credential_is_the_strongest_signal() -> None:
    deviations = score(established(), Observation(
        operation="tools/call echo",
        resource_kinds=frozenset({"aws:s3"}),
        credential_ref="AKIAUNSEENCREDENTIAL",
        hour=10,
    ))
    assert [d.dimension for d in deviations] == ["credential"]
    assert fires(deviations)
    assert "never used credential" in deviations[0].explanation


def test_an_unseen_operation_alone_does_not_fire() -> None:
    """One novel dimension is a normal day. Firing on it would make the rule
    noise; the score threshold is what keeps it meaningful."""
    deviations = score(established(), Observation(
        operation="tools/call brand-new",
        resource_kinds=frozenset({"aws:s3"}),
        credential_ref="AKIAIOSFODNN7EXAMPLE",
        hour=10,
    ))
    assert [d.dimension for d in deviations] == ["operation"]
    assert not fires(deviations)


def test_combined_novelty_fires() -> None:
    """A new operation touching a resource class this agent has never touched
    is the shape worth surfacing."""
    deviations = score(established(), Observation(
        operation="tools/call exfiltrate",
        resource_kinds=frozenset({"gh:repo"}),
        credential_ref="AKIAIOSFODNN7EXAMPLE",
        hour=10,
    ))
    assert {d.dimension for d in deviations} == {"operation", "resource_kind"}
    assert fires(deviations)


def test_an_unusual_hour_is_noticed_but_is_weak_alone() -> None:
    deviations = score(established(), Observation(
        operation="tools/call echo",
        resource_kinds=frozenset({"aws:s3"}),
        credential_ref="AKIAIOSFODNN7EXAMPLE",
        hour=3,
    ))
    assert [d.dimension for d in deviations] == ["hour"]
    assert not fires(deviations)


def test_a_busy_hour_is_not_unusual() -> None:
    assert score(established(), Observation(operation="tools/list", hour=12)) == []


def test_each_new_resource_kind_counts_separately() -> None:
    deviations = score(established(), Observation(
        operation="tools/list",
        resource_kinds=frozenset({"gh:repo", "gcp:bucket"}),
    ))
    assert [d.dimension for d in deviations] == ["resource_kind", "resource_kind"]
    assert fires(deviations)


# -- explainability -----------------------------------------------------------

def test_evidence_shows_the_baseline_next_to_the_observation() -> None:
    """This is the requirement made concrete: a reviewer must see what is
    normal, what happened, and the arithmetic between them."""
    observation = Observation(
        operation="tools/call exfiltrate",
        resource_kinds=frozenset({"gh:repo"}),
        credential_ref="AKIAUNSEEN",
        hour=3,
    )
    deviations = score(established(), observation)
    body = evidence(established(), observation, deviations)

    assert body["score"] >= body["fires_at"]
    assert body["baseline"]["days_observed"] == 30.0
    assert body["baseline"]["sessions"] == 40
    assert body["baseline"]["distinct_operations"] == 2
    assert body["observed"]["operation"] == "tools/call exfiltrate"
    assert body["observed"]["hour_utc"] == 3
    # Every deviation carries its own weight and a sentence explaining it.
    assert all(item["why"] and item["weight"] > 0 for item in body["deviations"])


def test_the_rule_produces_a_readable_alert() -> None:
    facts = EventFacts(
        event_id="e1", session_id="s1", agent_id="deploy-bot",
        operation="tools/call exfiltrate",
        baseline=established(),
        observation=Observation(
            operation="tools/call exfiltrate",
            resource_kinds=frozenset({"gh:repo"}),
            credential_ref="AKIAUNSEEN",
            hour=3,
        ),
    )
    alerts = [a for a in evaluate(facts) if a.rule_id == "behavioral_deviation"]
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"  # unseen credential
    assert "deploy-bot" in alerts[0].title
    assert "departed from its own 30-day baseline" in str(alerts[0].evidence["why"])


def test_severity_drops_without_a_credential_novelty() -> None:
    facts = EventFacts(
        event_id="e1", session_id="s1", agent_id="a",
        operation="tools/call new",
        baseline=established(),
        observation=Observation(
            operation="tools/call new",
            resource_kinds=frozenset({"gh:repo"}),
            credential_ref="AKIAIOSFODNN7EXAMPLE",
        ),
    )
    alerts = [a for a in evaluate(facts) if a.rule_id == "behavioral_deviation"]
    assert alerts[0].severity == "high"


def test_no_baseline_means_no_rule_8_alert() -> None:
    """A missing baseline is not an empty baseline; the deterministic rules
    must still run."""
    facts = EventFacts(
        event_id="e1", session_id="s1", agent_id="a", operation="files/delete",
    )
    candidates = evaluate(facts)
    assert not [a for a in candidates if a.rule_id == "behavioral_deviation"]
    # Rule 1 is unaffected.
    assert [a for a in candidates if a.rule_id == "destructive_operation"]
