"""SOC 2 / ISO 42001 control evidence.

The distinctive claim: for the controls Leaflyst actually ENFORCES, evidence is
collected by exercising the running system rather than by screenshotting a
settings page. So the tests here check two things a normal compliance module
would not:

- the append-only check genuinely attempts a forbidden mutation and reports the
  refusal, rather than reading a grant table and trusting it;
- controls the product CANNOT self-attest are present and marked manual. A
  readiness report that quietly omits them is worse than a short one, because
  the omission surfaces during the audit instead of before it.
"""

from __future__ import annotations

from abx_api.controls import CONTROLS, collect
from abx_api.main import app
from conftest import requires_stack
from fastapi.testclient import TestClient

ADMIN = {"X-Abx-Admin-Key": "dev-admin-key"}


# -- catalogue -----------------------------------------------------------------

def test_every_control_maps_to_both_frameworks() -> None:
    for control in CONTROLS:
        assert control.soc2, control.control_id
        assert control.iso42001, control.control_id
        assert control.statement.endswith("."), control.control_id


def test_control_ids_are_unique() -> None:
    ids = [control.control_id for control in CONTROLS]
    assert len(ids) == len(set(ids))


def test_a_control_is_either_checkable_or_declares_what_is_needed() -> None:
    """No control may be silently unproven."""
    for control in CONTROLS:
        assert control.check is not None or control.manual_evidence, control.control_id


def test_manual_controls_cover_the_process_gaps() -> None:
    """Access review, change management, incident response, vendors, and pen
    test are real SOC 2 expectations the product cannot attest to itself."""
    manual = {c.control_id for c in CONTROLS if c.check is None}
    assert len(manual) >= 5
    statements = " ".join(c.statement for c in CONTROLS if c.check is None).lower()
    for expected in ("access", "change", "incident", "subprocessor", "penetration"):
        assert expected in statements


# -- live collection -----------------------------------------------------------

@requires_stack
def test_append_only_control_is_exercised_not_asserted(tenant) -> None:
    """The proof is that a mutation attempt is refused right now, not that a
    grant table says it would be."""
    report = collect()
    control = next(
        item for item in report["automated"] if item["control_id"] == "LFY-1"
    )
    assert control["passed"] is True
    assert control["evidence"]["attempted"].startswith("ALTER TABLE events")
    assert control["evidence"]["refused_with"]


@requires_stack
def test_key_lifecycle_control_reflects_reality(tenant) -> None:
    report = collect()
    control = next(i for i in report["automated"] if i["control_id"] == "LFY-4")
    assert control["passed"] is True


@requires_stack
def test_least_privilege_control_names_the_roles(tenant) -> None:
    report = collect()
    control = next(i for i in report["automated"] if i["control_id"] == "LFY-7")
    assert control["passed"] is True
    assert control["evidence"]["roles_that_may_configure"] == ["admin"]
    assert set(control["evidence"]["roles"]) == {
        "viewer", "responder", "auditor", "admin",
    }


@requires_stack
def test_read_only_scan_control_lists_the_client_surfaces(tenant) -> None:
    """The guarantee is the absence of a write path, so the evidence is the
    public surface of each client."""
    report = collect()
    control = next(i for i in report["automated"] if i["control_id"] == "LFY-6")
    assert control["passed"] is True
    assert control["evidence"]["offenders"] == {}
    assert set(control["evidence"]["client_surfaces"]) == {"azure", "gcp", "workspace"}


@requires_stack
def test_redaction_control_enumerates_the_rules_in_force(tenant) -> None:
    report = collect()
    control = next(i for i in report["automated"] if i["control_id"] == "LFY-5")
    assert control["evidence"]["rule_count"] >= 1
    assert control["evidence"]["producer_can_disable"] is False


@requires_stack
def test_the_report_counts_what_it_could_and_could_not_prove(tenant) -> None:
    report = collect()
    summary = report["summary"]
    assert summary["automated_controls"] == len(report["automated"])
    assert summary["manual_controls"] == len(report["manual"])
    assert summary["automated_passing"] + summary["automated_failing"] == (
        summary["automated_controls"]
    )
    assert all(item["evidence_required"] for item in report["manual"])


@requires_stack
def test_the_report_does_not_claim_certification(tenant) -> None:
    """Readiness is not an opinion on either framework, and saying otherwise
    would be the fastest way to make the artifact worthless in an audit."""
    note = collect()["scope_note"].lower()
    assert "readiness is not certification" in note
    assert "assessor" in note


@requires_stack
def test_a_failing_check_does_not_break_the_report(monkeypatch, tenant) -> None:
    """An erroring control is a failing control, not a 500."""
    import abx_api.controls as controls_module

    def explode() -> None:
        raise RuntimeError("clickhouse unreachable")

    original = controls_module.CONTROLS
    monkeypatch.setattr(
        controls_module, "CONTROLS",
        tuple(
            controls_module.Control(
                c.control_id, c.statement, c.soc2, c.iso42001,
                explode if c.control_id == "LFY-1" else c.check, c.manual_evidence,
            )
            for c in original
        ),
    )
    report = collect()
    control = next(i for i in report["automated"] if i["control_id"] == "LFY-1")
    assert control["passed"] is False
    assert "could not be completed" in control["detail"]


# -- endpoint ------------------------------------------------------------------

@requires_stack
def test_the_endpoint_requires_export_capability(tenant) -> None:
    tenant_id, _ = tenant
    client = TestClient(app)
    viewer = client.post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": "v", "role": "viewer"}, headers=ADMIN,
    ).json()["token"]
    assert client.get(
        "/v1/compliance/controls", headers={"Authorization": f"Bearer {viewer}"}
    ).status_code == 403

    auditor = client.post(
        f"/v1/settings/read-tokens?tenant_id={tenant_id}",
        json={"label": "a", "role": "auditor"}, headers=ADMIN,
    ).json()["token"]
    response = client.get(
        "/v1/compliance/controls", headers={"Authorization": f"Bearer {auditor}"}
    )
    assert response.status_code == 200
    assert response.json()["format"] == "abx-control-report-v1"
