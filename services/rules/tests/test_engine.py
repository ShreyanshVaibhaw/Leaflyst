from abx_rules import EventFacts, evaluate


def _facts(**updates: object) -> EventFacts:
    values: dict[str, object] = {
        "event_id": "event", "session_id": "session", "agent_id": "agent",
        "operation": "read", "credential_ref": None,
    }
    values.update(updates)
    return EventFacts(**values)  # type: ignore[arg-type]


def test_immediate_rules_are_explainable() -> None:
    alerts = evaluate(_facts(
        operation="delete database", scanner_baseline=True,
        credential_flagged=True, environment_crossover=True,
        tool_inventory_drift=True,
    ))
    assert [alert.rule_id for alert in alerts] == [
        "destructive_operation", "credential_outside_scope",
        "environment_crossover", "tool_inventory_drift",
    ]


def test_history_rule_stays_silent_until_seven_days() -> None:
    cold = evaluate(_facts(
        history_days=6.99, session_event_count=101, trailing_session_median=10,
    ))
    warm = evaluate(_facts(
        history_days=7, session_event_count=51, trailing_session_median=10,
    ))
    assert not cold
    assert [alert.rule_id for alert in warm] == ["action_volume_spike"]
