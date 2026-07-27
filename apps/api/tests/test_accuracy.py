"""Deterministic accuracy benchmark for the curated rule corpus."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from abx_api.redaction import RULES, redact
from abx_rules import EventFacts, evaluate
from abx_scanner.findings import _gcp_rules, _github_rules, _rules_for_credential

FINDING_TYPES = {
    "orphaned_credential",
    "over_privileged",
    "stale_authorization",
    "blast_radius",
}
ALERT_RULES = {
    "destructive_operation",
    "credential_outside_scope",
    "action_volume_spike",
    "environment_crossover",
    "tool_inventory_drift",
}


@dataclass(frozen=True)
class Metrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


def _metrics(expected: list[bool], actual: list[bool]) -> Metrics:
    tp = sum(want and got for want, got in zip(expected, actual, strict=True))
    fp = sum(not want and got for want, got in zip(expected, actual, strict=True))
    fn = sum(want and not got for want, got in zip(expected, actual, strict=True))
    tn = sum(not want and not got for want, got in zip(expected, actual, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return Metrics(
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=tn,
        precision=precision,
        recall=recall,
        f1=2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        false_positive_rate=fp / (fp + tn) if fp + tn else 0.0,
    )


def _finding_metrics() -> tuple[dict[str, Metrics], float]:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    risky_reach = {
        "count": 1,
        "resources": ["prod"],
        "destructive": True,
        "destructive_actions": ["admin"],
        "admin_wildcard": True,
        "hits_prod_or_wildcard": True,
        "access_levels": ["admin"],
        "scopes": ["*"],
    }
    safe_reach = {
        "count": 1,
        "resources": ["docs"],
        "destructive": False,
        "destructive_actions": [],
        "admin_wildcard": False,
        "hits_prod_or_wildcard": False,
        "access_levels": ["read"],
        "scopes": ["read"],
    }
    cases: dict[str, list[tuple[set[str], list[Any]]]] = {
        "aws": [
            (
                FINDING_TYPES,
                _rules_for_credential(
                    "1",
                    "aws-risk",
                    now - timedelta(days=31),
                    now - timedelta(days=91),
                    "active",
                    "arn:aws:iam::1:user/risk",
                    risky_reach,
                    now,
                ),
            ),
            (
                {"blast_radius"},
                _rules_for_credential(
                    "2",
                    "aws-safe",
                    now - timedelta(days=30),
                    now - timedelta(days=90),
                    "active",
                    "arn:aws:iam::1:user/safe",
                    safe_reach,
                    now,
                ),
            ),
        ],
        "github": [
            (
                FINDING_TYPES,
                _github_rules(
                    "3",
                    "gh-risk",
                    "fine_grained_pat",
                    now - timedelta(days=31),
                    now - timedelta(days=91),
                    "risk",
                    risky_reach,
                    now,
                ),
            ),
            (
                {"blast_radius"},
                _github_rules(
                    "4",
                    "gh-safe",
                    "fine_grained_pat",
                    now - timedelta(days=30),
                    now - timedelta(days=90),
                    "safe",
                    safe_reach,
                    now,
                ),
            ),
        ],
        "gcp": [
            (
                {"over_privileged", "stale_authorization", "blast_radius"},
                _gcp_rules(
                    "5",
                    "gcp-risk",
                    now - timedelta(days=91),
                    "risk@example.invalid",
                    risky_reach,
                    now,
                ),
            ),
            (
                {"blast_radius"},
                _gcp_rules(
                    "6",
                    "gcp-safe",
                    now - timedelta(days=90),
                    "safe@example.invalid",
                    safe_reach,
                    now,
                ),
            ),
        ],
    }
    report: dict[str, Metrics] = {}
    critical_expected = critical_found = 0
    for provider, provider_cases in cases.items():
        expected: list[bool] = []
        actual: list[bool] = []
        for wanted, findings in provider_cases:
            found = {finding.finding_type for finding in findings}
            expected.extend(kind in wanted for kind in FINDING_TYPES)
            actual.extend(kind in found for kind in FINDING_TYPES)
            critical_expected += int("over_privileged" in wanted)
            critical_found += any(
                finding.finding_type == "over_privileged"
                and finding.severity == "critical"
                for finding in findings
            )
        report[f"scanner:{provider}"] = _metrics(expected, actual)
    return report, critical_found / critical_expected


def _facts(**updates: object) -> EventFacts:
    values: dict[str, object] = {
        "event_id": "event",
        "session_id": "session",
        "agent_id": "agent",
        "operation": "read",
    }
    values.update(updates)
    return EventFacts(**values)  # type: ignore[arg-type]


def _alert_metrics() -> tuple[dict[str, Metrics], float]:
    cases = [
        ({"destructive_operation"}, _facts(operation="drop database")),
        (set(), _facts(operation="open dropdown menu")),
        (
            {"credential_outside_scope"},
            _facts(scanner_baseline=True, outside_scanned_scope=True),
        ),
        (set(), _facts(scanner_baseline=False, outside_scanned_scope=True)),
        (
            {"action_volume_spike"},
            _facts(history_days=7, session_event_count=51, trailing_session_median=10),
        ),
        (
            set(),
            _facts(history_days=7, session_event_count=50, trailing_session_median=10),
        ),
        ({"environment_crossover"}, _facts(environment_crossover=True)),
        (set(), _facts(environment_crossover=False)),
        ({"tool_inventory_drift"}, _facts(tool_inventory_drift=True)),
        (set(), _facts(tool_inventory_drift=False)),
    ]
    found = [{alert.rule_id for alert in evaluate(facts)} for _, facts in cases]
    report = {
        f"alert:{rule}": _metrics(
            [rule in wanted for wanted, _ in cases],
            [rule in actual for actual in found],
        )
        for rule in ALERT_RULES
    }
    critical = {"destructive_operation", "credential_outside_scope"}
    expected = sum(rule in wanted for wanted, _ in cases for rule in critical)
    actual = sum(
        rule in result and rule in wanted
        for (wanted, _), result in zip(cases, found, strict=True)
        for rule in critical
    )
    return report, actual / expected


def _redaction_metrics() -> dict[str, Metrics]:
    positives = [
        ("AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws-secret-key"),
        ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", "github-token"),
        (
            "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "github-fine-grained-pat",
        ),
        ("xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "slack-token"),
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6y",
            "jwt",
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7bq0\n-----END PRIVATE KEY-----",
            "pem-private-key",
        ),
        ("Authorization: Bearer sk-live-abcDEF123456789", "authorization-header"),
        (
            "postgresql://svc_agent:sup3rS3cretPW@db.internal:5432/prod",
            "connection-string-password",
        ),
        ("OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmn", "generic-api-key-assignment"),
    ]
    benign = [
        "the agent listed three files",
        "AWS_ACCESS_KEY_ID is not configured",
        "use Authorization: Bearer <token>",
        "postgresql://localhost:5432/dev",
        "github.com/example/repository",
        "drop-down menu selected",
        "client_secret is loaded from the environment",
        "xoxb tokens begin with a documented prefix",
        "JWT validation failed",
        "-----BEGIN PUBLIC KEY-----",
        "AKIA is an AWS access-key prefix",
        "api_key=<redacted>",
    ]
    cases: list[tuple[set[str], set[str]]] = []
    for text, expected_rule in positives:
        scrubbed, fired = redact(text)
        assert text not in scrubbed
        cases.append(({expected_rule}, set(fired)))
    cases.extend((set(), set(redact(text)[1])) for text in benign)
    return {
        f"redaction:{rule.id}": _metrics(
            [rule.id in wanted for wanted, _ in cases],
            [rule.id in found for _, found in cases],
        )
        for rule in RULES
    }


def test_curated_accuracy_thresholds() -> None:
    scanner, scanner_critical_recall = _finding_metrics()
    alerts, alert_critical_recall = _alert_metrics()
    report = scanner | alerts | _redaction_metrics()

    for name, metrics in report.items():
        if name.startswith("redaction:"):
            assert metrics.recall == 1.0
            assert metrics.false_positive_rate < 0.01
        else:
            assert metrics.precision >= 0.95
            assert metrics.recall >= 0.95
            assert metrics.f1 >= 0.95
            assert metrics.false_positive_rate <= 0.05
    assert scanner_critical_recall == 1.0
    assert alert_critical_recall == 1.0

    print(
        json.dumps(
            {
                "metrics": {name: asdict(metrics) for name, metrics in sorted(report.items())},
                "scanner_critical_recall": scanner_critical_recall,
                "alert_critical_recall": alert_critical_recall,
                "scope": "curated deterministic corpus; not real-provider accuracy",
            },
            sort_keys=True,
        )
    )
