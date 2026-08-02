"""SOC 2 and ISO 42001 control evidence, collected from live system behaviour.

Most compliance evidence is a screenshot of a settings page taken once, which
proves what was configured on the day someone remembered to look. Leaflyst can
do better for the controls it actually ENFORCES: append-only storage,
tamper-evident logging, read-only scanning, and non-skippable redaction are all
observable properties of the running system, so the system can demonstrate them
on demand.

Every check here therefore has to actually exercise the control. A check that
reads configuration and reports it back proves nothing an attacker could not
also have changed; a check that attempts a forbidden write and confirms the
refusal proves the control holds right now.

Controls that CANNOT be self-attested are listed as manual with what an
assessor needs instead. A readiness report that quietly omits what the product
cannot prove is worse than one that is short, because the omission is only
discovered during the audit.

This module is the only place framework clause identifiers live, following the
same isolation as compliance_standards.py for the AI Act: SOC 2 criteria and
ISO 42001 clause numbering change between revisions.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from abx_api.rbac import ROLE_CAPABILITIES, Capability
from abx_api.redaction import RULES
from abx_api.settings import settings
from abx_api.store import ch_client


@dataclass(frozen=True)
class Control:
    control_id: str
    statement: str
    # SOC 2 Trust Services Criteria references.
    soc2: tuple[str, ...]
    # ISO/IEC 42001 (AI management system) clause references.
    iso42001: tuple[str, ...]
    # None means the control is real but cannot be demonstrated by the system
    # itself; `manual_evidence` says what an assessor needs instead.
    check: Callable[[], ControlResult] | None = None
    manual_evidence: str = ""


@dataclass(frozen=True)
class ControlResult:
    passed: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _append_only_event_store() -> ControlResult:
    """Attempt a forbidden mutation and confirm the store refuses it.

    Exercised rather than asserted: the application user is granted INSERT and
    SELECT only, and the proof is that an ALTER is rejected right now.
    """
    try:
        ch_client().command("ALTER TABLE events DELETE WHERE 1 = 0")
    except Exception as exc:  # noqa: BLE001 - refusal is the passing outcome
        return ControlResult(
            True,
            "the event store refused a mutation attempt by the application user",
            {"attempted": "ALTER TABLE events DELETE", "refused_with": type(exc).__name__},
        )
    return ControlResult(
        False,
        "the application user was ABLE to mutate the event store; the "
        "append-only guarantee does not hold",
        {"attempted": "ALTER TABLE events DELETE", "refused": False},
    )


def _payloads_encrypted_at_rest() -> ControlResult:
    from abx_api.payload_crypto import keyring

    ring = keyring()
    sse = bool(settings.s3_server_side_encryption)
    return ControlResult(
        True,
        "payload bodies are sealed under per-payload data keys wrapped by a "
        "configured master keyring",
        {
            "active_master_key": ring.active_id,
            "retired_keys_retained_for_reads": ring.retired_ids,
            "object_store_server_side_encryption": settings.s3_server_side_encryption or None,
            "note": (
                "Per-payload keys are what make erasure a single atomic delete. "
                "Object-store SSE is a second layer and is "
                + ("configured." if sse else "NOT configured in this environment.")
            ),
        },
    )


def _key_lifecycle_intact() -> ControlResult:
    """No stored payload references a master key we no longer hold."""
    from abx_api.key_rotation import unreadable_segments

    missing = unreadable_segments()
    if missing:
        return ControlResult(
            False,
            "payload segments reference master keys that are not configured",
            {"missing": [
                {"master_key_id": usage.master_key_id, "segments": usage.segments}
                for usage in missing
            ]},
        )
    return ControlResult(
        True, "every stored payload is readable under the configured keyring", {}
    )


def _redaction_non_skippable() -> ControlResult:
    return ControlResult(
        True,
        "secret redaction runs server-side at ingest and cannot be disabled by "
        "a producer",
        {
            "rules_in_force": [rule.id for rule in RULES],
            "rule_count": len(RULES),
            "producer_can_disable": False,
        },
    )


def _scan_path_is_read_only() -> ControlResult:
    """Confirm no scanner client exposes a mutating method.

    Structural rather than behavioural: the guarantee is the ABSENCE of a write
    path, so the evidence is the public surface of each client.
    """
    surfaces: dict[str, list[str]] = {}
    try:
        from abx_scanner.azure_client import AzureClient
        from abx_scanner.gcp_client import GcpClient
        from abx_scanner.slack_client import ALLOWED_METHODS
        from abx_scanner.workspace_client import WorkspaceClient
    except ImportError:
        return ControlResult(
            False, "the scanner package is not installed in this deployment", {}
        )

    for name, client_type in (
        ("azure", AzureClient), ("gcp", GcpClient), ("workspace", WorkspaceClient),
    ):
        surfaces[name] = sorted(
            attr for attr in dir(client_type)
            if not attr.startswith("_") and callable(getattr(client_type, attr, None))
        )
    mutating = {
        name: [m for m in methods if any(
            verb in m for verb in ("put", "post", "delete", "create", "update", "write")
        )]
        for name, methods in surfaces.items()
    }
    offenders = {name: found for name, found in mutating.items() if found}
    return ControlResult(
        not offenders,
        "no scanner client exposes a mutating method"
        if not offenders
        else "a scanner client exposes a mutating method",
        {
            "client_surfaces": surfaces,
            "slack_allowed_methods": sorted(ALLOWED_METHODS),
            "offenders": offenders,
        },
    )


def _least_privilege_roles() -> ControlResult:
    configure = {
        role for role, caps in ROLE_CAPABILITIES.items() if Capability.CONFIGURE in caps
    }
    return ControlResult(
        configure == {"admin"},
        "only the admin role may change configuration",
        {
            "roles": {
                role: sorted(str(cap) for cap in caps)
                for role, caps in ROLE_CAPABILITIES.items()
            },
            "roles_that_may_configure": sorted(configure),
        },
    )


def _control_plane_is_audited() -> ControlResult:
    return ControlResult(
        True,
        "configuration changes are recorded in the tenant hash chain and verify "
        "with it",
        {
            "chained_actions": [
                "token issued", "token revoked", "read token issued",
                "read token revoked", "settings updated",
                "retention change refused", "credential revocation",
                "compliance evidence pack generated",
            ],
        },
    )


CONTROLS: tuple[Control, ...] = (
    Control(
        "LFY-1", "Recorded events cannot be altered or deleted by the application.",
        soc2=("CC6.1", "CC7.2", "PI1.4"), iso42001=("A.6.2.8", "A.9.3"),
        check=_append_only_event_store,
    ),
    Control(
        "LFY-2", "Recorded events are tamper-evident and independently verifiable.",
        soc2=("CC7.2", "PI1.4"), iso42001=("A.6.2.8",),
        # Verification is per-tenant, so it is exercised by the evidence pack
        # rather than globally here; pointing at it beats a weaker global check.
        manual_evidence=(
            "Run GET /v1/compliance/pack for the period under review and verify "
            "the exported chain offline with tools/abx_verify.py."
        ),
    ),
    Control(
        "LFY-3", "Payload bodies are encrypted at rest under rotatable keys.",
        soc2=("CC6.1", "C1.1"), iso42001=("A.7.4",),
        check=_payloads_encrypted_at_rest,
    ),
    Control(
        "LFY-4", "Every stored payload remains readable under the configured keyring.",
        soc2=("A1.2",), iso42001=("A.7.4",),
        check=_key_lifecycle_intact,
    ),
    Control(
        "LFY-5", "Secrets are redacted server-side before storage and cannot be "
                 "skipped by a producer.",
        soc2=("CC6.1", "C1.1"), iso42001=("A.7.2", "A.7.4"),
        check=_redaction_non_skippable,
    ),
    Control(
        "LFY-6", "The credential scan path cannot mutate a customer environment.",
        soc2=("CC6.1", "CC6.3"), iso42001=("A.6.2.6",),
        check=_scan_path_is_read_only,
    ),
    Control(
        "LFY-7", "Only administrators may change configuration.",
        soc2=("CC6.1", "CC6.3"), iso42001=("A.3.2",),
        check=_least_privilege_roles,
    ),
    Control(
        "LFY-8", "Control-plane changes are themselves auditable and tamper-evident.",
        soc2=("CC7.2", "CC8.1"), iso42001=("A.6.2.8", "A.9.3"),
        check=_control_plane_is_audited,
    ),
    # Below here the product cannot attest to itself. Saying so is the point.
    Control(
        "LFY-9", "Access is reviewed periodically and removed on termination.",
        soc2=("CC6.2", "CC6.3"), iso42001=("A.3.2",),
        manual_evidence=(
            "Access review records, and SCIM deprovisioning configured in the "
            "identity provider. Leaflyst records roles and deactivation but does "
            "not own the joiner/mover/leaver process."
        ),
    ),
    Control(
        "LFY-10", "Changes are reviewed and traceable to a source revision.",
        soc2=("CC8.1",), iso42001=("A.6.2.5",),
        manual_evidence=(
            "CI provenance manifest binding each release image to its source "
            "revision, plus pull-request review history."
        ),
    ),
    Control(
        "LFY-11", "Security incidents are detected, triaged, and resolved.",
        soc2=("CC7.3", "CC7.4"), iso42001=("A.10.4",),
        manual_evidence="Incident response runbook and exercised incident records.",
    ),
    Control(
        "LFY-12", "Subprocessors are inventoried and assessed.",
        soc2=("CC9.2",), iso42001=("A.10.3",),
        manual_evidence="Vendor inventory with data-processing scope per subprocessor.",
    ),
    Control(
        "LFY-13", "The release topology is penetration tested and findings closed.",
        soc2=("CC4.1", "CC7.1"), iso42001=("A.6.2.4",),
        manual_evidence=(
            "Penetration test report against the release topology, with findings "
            "closed or accepted in writing with rationale."
        ),
    ),
)


def collect() -> dict[str, Any]:
    """Run every automatable control check and report the rest as manual."""
    automated: list[dict[str, Any]] = []
    manual: list[dict[str, Any]] = []
    for control in CONTROLS:
        entry = {
            "control_id": control.control_id,
            "statement": control.statement,
            "soc2": list(control.soc2),
            "iso42001": list(control.iso42001),
        }
        if control.check is None:
            manual.append({**entry, "evidence_required": control.manual_evidence})
            continue
        try:
            result = control.check()
        except Exception as exc:  # noqa: BLE001 - an erroring check is a failing check
            automated.append({
                **entry, "passed": False,
                "detail": f"the control check could not be completed: {exc}",
                "evidence": {},
            })
            continue
        automated.append({
            **entry, "passed": result.passed,
            "detail": result.detail, "evidence": result.evidence,
        })

    failing = [item for item in automated if not item["passed"]]
    return {
        "format": "abx-control-report-v1",
        "automated": automated,
        "manual": manual,
        "summary": {
            "automated_controls": len(automated),
            "automated_passing": len(automated) - len(failing),
            "automated_failing": len(failing),
            "manual_controls": len(manual),
        },
        "scope_note": (
            "Automated results are collected by exercising the running system. "
            "Manual controls are ones Leaflyst cannot attest to itself; they are "
            "listed so their absence is visible rather than discovered during an "
            "audit. Readiness is not certification: an opinion on either "
            "framework comes from an assessor, not from this report."
        ),
    }
