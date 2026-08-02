"""Regulatory vocabulary - the ONLY module that knows clause text and ids.

Same discipline as the SDK's conventions.py for OTel gen_ai.* and the tap's
mcp_spec.py for MCP wire names: an external vocabulary that churns lives in one
place, so a change lands here instead of scattering.

This one is guaranteed to churn. As of July 2026 there is no finalised
technical standard for Article 12 logging. Two drafts are in flight:

- prEN 18229-1 (AI logging and human oversight)
- ISO/IEC DIS 24970 (AI system logging)

When either lands, its clause mapping is added here and nothing else moves.

Nothing in this module asserts that a customer's system IS high-risk under the
AI Act, or that they ARE compliant. That determination is the deployer's, not
a vendor's. What Leaflyst states is narrower and checkable: which artifact it
produces for each clause, and how to verify that artifact independently.
"""

from __future__ import annotations

from dataclasses import dataclass

# Enforcement for high-risk systems begins on this date.
AI_ACT_HIGH_RISK_APPLICATION_DATE = "2026-08-02"

# Article 12(1) wording is "at least six months" unless other law says longer.
ARTICLE_12_MINIMUM_RETENTION_DAYS = 180


@dataclass(frozen=True)
class ClauseMapping:
    clause: str
    requirement: str
    artifact: str
    how_to_check: str


# Each entry answers one auditor question: what does the regulation ask for,
# what in this pack answers it, and how do I confirm that myself?
ARTICLE_12_MAPPING: tuple[ClauseMapping, ...] = (
    ClauseMapping(
        clause="Article 12(1)",
        requirement=(
            "The system automatically records events over its lifetime."
        ),
        artifact="chain.ndjson - every recorded event, in chain order.",
        how_to_check=(
            "The event store grants the application user INSERT and SELECT only; "
            "it holds no UPDATE, DELETE, or ALTER grant, so recorded events "
            "cannot be edited by the recording path at all."
        ),
    ),
    ClauseMapping(
        clause="Article 12(2)(a)",
        requirement=(
            "Logging supports identifying situations that may present a risk."
        ),
        artifact="alerts and findings referenced from the events they fired on.",
        how_to_check=(
            "Each alert deep-links to the event that triggered it; the rule and "
            "its baseline are shown alongside the observation."
        ),
    ),
    ClauseMapping(
        clause="Article 12(2)(b)",
        requirement="Logging supports post-market monitoring.",
        artifact="the period summary and per-agent activity in this manifest.",
        how_to_check="Counts here are derived from the same chain in chain.ndjson.",
    ),
    ClauseMapping(
        clause="Article 12(3)",
        requirement=(
            "Records identify the natural persons involved in verification."
        ),
        artifact="operator_roster - the operator of record for each session.",
        how_to_check=(
            "operator_ref is inside the hashed field set, and is bound to the "
            "ingest token rather than supplied by the recorded agent, so it "
            "cannot be forged by the thing being recorded or altered afterwards."
        ),
    ),
    ClauseMapping(
        clause="Article 19 / Article 12(1)",
        requirement=(
            "Logs are retained for an appropriate period, at least six months."
        ),
        artifact="retention_policy, including the floor in force.",
        how_to_check=(
            "A tenant in compliance mode cannot lower retention below the floor "
            "by any API path; a refused attempt is itself recorded in the chain "
            "as a denied event."
        ),
    ),
)

# Drafts tracked but not yet mappable. Stated so a reader is not left to assume
# this pack claims conformance with a standard that does not exist yet.
DRAFT_STANDARDS: tuple[dict[str, str], ...] = (
    {
        "id": "prEN 18229-1",
        "title": "AI logging and human oversight",
        "status": "draft as of 2026-07-30; no clause mapping published here yet",
    },
    {
        "id": "ISO/IEC DIS 24970",
        "title": "AI system logging",
        "status": "draft as of 2026-07-30; no clause mapping published here yet",
    },
)


def clause_mapping() -> list[dict[str, str]]:
    return [
        {
            "clause": entry.clause,
            "requirement": entry.requirement,
            "artifact": entry.artifact,
            "how_to_check": entry.how_to_check,
        }
        for entry in ARTICLE_12_MAPPING
    ]
