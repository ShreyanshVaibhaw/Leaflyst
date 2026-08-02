"""Runtime policy decisions (plan2 phase 25, blueprint2 19).

The constraint that outranks every feature here: enforcement must never be able
to degrade recording. The product's failure mode is "agent keeps working,
recording degrades", and a plane that can deny an action can also fail and stop
the agent. So the failure semantics get more tests than the matching does.

Fail-closed exists but must be chosen explicitly, per policy. A product that
silently fails closed will eventually take down a customer's production and be
technically right about it, which is not a defence anyone accepts.
"""

from __future__ import annotations

from abx_rules.policy import (
    Decision,
    Effect,
    OnError,
    Policy,
    PolicyRequest,
    decide,
    on_evaluation_failure,
)


def deny(**overrides: object) -> Policy:
    base: dict[str, object] = {
        "policy_id": "no-destructive", "version": 1, "effect": Effect.DENY,
        "match_destructive": True, "description": "destructive operations are blocked",
    }
    base.update(overrides)
    return Policy(**base)  # type: ignore[arg-type]


def request(**overrides: object) -> PolicyRequest:
    base: dict[str, object] = {"operation": "files/delete", "agent_id": "bot"}
    base.update(overrides)
    return PolicyRequest(**base)  # type: ignore[arg-type]


# -- failure semantics ---------------------------------------------------------

def test_evaluation_failure_allows_by_default() -> None:
    """An outage of ours must not become an outage of theirs."""
    decision = on_evaluation_failure([deny()], "database unreachable")
    assert decision.allowed
    assert decision.degraded
    assert "no policy is fail-closed" in decision.reason


def test_fail_closed_must_be_opted_into_per_policy() -> None:
    decision = on_evaluation_failure([deny(on_error=OnError.DENY)], "timeout")
    assert not decision.allowed
    assert decision.degraded
    assert "fail-closed" in decision.reason


def test_a_disabled_fail_closed_policy_does_not_close() -> None:
    """Disabling a policy must disable it completely, including its failure
    behaviour - otherwise turning a policy off makes things stricter."""
    decision = on_evaluation_failure(
        [deny(on_error=OnError.DENY, enabled=False)], "timeout"
    )
    assert decision.allowed


def test_a_degraded_decision_is_marked_as_such() -> None:
    """A degraded allow must not read as an approval: the difference between
    'we considered this and permitted it' and 'we could not evaluate' is the
    whole value of the record."""
    allowed = decide([deny()], request(operation="tools/list"))
    degraded = on_evaluation_failure([deny()], "boom")
    assert allowed.allowed and not allowed.degraded
    assert degraded.allowed and degraded.degraded


# -- matching ------------------------------------------------------------------

def test_no_policy_means_allowed() -> None:
    """Policy is opt-in per action, not a default-deny posture the customer did
    not ask for."""
    decision = decide([], request())
    assert decision.allowed
    assert decision.policy_id is None
    assert "no policy matched" in decision.reason


def test_a_destructive_operation_is_denied() -> None:
    decision = decide([deny()], request(operation="files/delete"))
    assert not decision.allowed
    assert decision.policy_id == "no-destructive"
    assert decision.reason == "destructive operations are blocked"


def test_a_non_destructive_operation_passes() -> None:
    assert decide([deny()], request(operation="tools/list")).allowed


def test_an_empty_policy_matches_nothing() -> None:
    """A half-written deny must not become a deny-everything."""
    empty = Policy(policy_id="oops", version=1, effect=Effect.DENY)
    assert empty.is_empty
    assert decide([empty], request(operation="files/delete")).allowed


def test_a_disabled_policy_does_not_match() -> None:
    assert decide([deny(enabled=False)], request(operation="files/delete")).allowed


def test_an_explicit_allow_short_circuits_a_later_deny() -> None:
    """What makes a narrow exemption expressible."""
    exemption = Policy(
        policy_id="allow-cleanup-bot", version=1, effect=Effect.ALLOW,
        match_agents=("cleanup-bot",),
    )
    decision = decide([exemption, deny()], request(agent_id="cleanup-bot"))
    assert decision.allowed
    assert decision.policy_id == "allow-cleanup-bot"
    # A different agent still hits the deny.
    assert not decide([exemption, deny()], request(agent_id="other")).allowed


def test_all_declared_conditions_must_match() -> None:
    scoped = deny(match_destructive=True, match_agents=("bot",))
    assert not decide([scoped], request(operation="files/delete", agent_id="bot")).allowed
    assert decide([scoped], request(operation="files/delete", agent_id="other")).allowed


def test_operation_patterns_support_a_trailing_wildcard() -> None:
    policy = Policy(
        policy_id="no-writes", version=1, effect=Effect.DENY,
        match_operations=("tools/call write-*",),
    )
    assert not decide([policy], request(operation="tools/call write-file")).allowed
    assert decide([policy], request(operation="tools/call read-file")).allowed


def test_resource_prefixes_match_any_touched_resource() -> None:
    policy = Policy(
        policy_id="no-prod", version=1, effect=Effect.DENY,
        match_resource_prefixes=("aws:s3:prod-",),
    )
    assert not decide([policy], request(
        resource_refs=("aws:s3:dev-bucket", "aws:s3:prod-secrets"),
    )).allowed
    assert decide([policy], request(resource_refs=("aws:s3:dev-bucket",))).allowed


def test_tool_matching_is_exact() -> None:
    policy = Policy(
        policy_id="no-shell", version=1, effect=Effect.DENY, match_tools=("shell",),
    )
    assert not decide([policy], request(tool_name="shell")).allowed
    assert decide([policy], request(tool_name="shell-safe")).allowed


def test_the_decision_records_what_was_evaluated() -> None:
    """An operator has to be able to see which policies were considered, not
    only which one won."""
    first = Policy(
        policy_id="watch", version=1, effect=Effect.ALLOW, match_agents=("bot",),
    )
    decision = decide([first, deny()], request(agent_id="bot"))
    assert decision.evaluated == ("watch",)


def test_the_matched_version_is_reported() -> None:
    """A customer must be able to say which policy VERSION was in force."""
    decision = decide([deny(version=7)], request(operation="files/delete"))
    assert decision.policy_version == 7


# -- the vocabulary is shared with the rules -----------------------------------

def test_policy_and_rule_1_agree_on_what_is_destructive() -> None:
    """The destructive lexicon is the same object rule 1 fires on, so what the
    product warns about and what it can block cannot drift apart."""
    from abx_rules import EventFacts, evaluate
    from abx_rules.engine import DESTRUCTIVE
    from abx_rules.policy import DESTRUCTIVE as POLICY_DESTRUCTIVE

    assert DESTRUCTIVE is POLICY_DESTRUCTIVE
    for operation in ("files/delete", "db/drop table", "repo/force-push"):
        warned = [
            a for a in evaluate(EventFacts(
                event_id="e", session_id="s", agent_id="a", operation=operation,
            )) if a.rule_id == "destructive_operation"
        ]
        blocked = not decide([deny()], request(operation=operation)).allowed
        assert bool(warned) == blocked, operation


def test_decision_is_a_value_not_an_exception() -> None:
    """Callers must never have to catch to get an answer; a plane that raises
    into the tap's path is how enforcement takes down an agent."""
    assert isinstance(decide([], request()), Decision)
    assert isinstance(on_evaluation_failure([], "x"), Decision)
