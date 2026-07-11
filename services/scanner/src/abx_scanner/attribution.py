"""Agent-attribution heuristics (blueprint 5.3).

Decides whether an IAM principal is plausibly an AGENT credential (vs a human
or generic service account). Cheap signals only at MVP; the strongest signal -
a credential actually observed in recorder traffic - is applied later (Phase
5/6) when the recorder graph links up.
"""

from __future__ import annotations

import re

from abx_scanner.aws import Principal

_AGENTY_NAME = re.compile(
    r"(?i)(^|[-_])(svc|service|agent|bot|mcp|worker|automation|ci|deploy|"
    r"langgraph|langchain|crewai|autogen|openai|anthropic)([-_]|$)"
)


def is_probable_agent(principal: Principal) -> bool:
    """Best-effort: name pattern OR programmatic-only user with keys.

    A programmatic-only IAM user (no console login) that holds access keys is
    service-like; combined with the name heuristic this catches most agent
    credentials. The strongest signal - the credential appearing in recorder
    traffic - is applied in Phase 5/6.
    """
    if _AGENTY_NAME.search(principal.name):
        return True
    return bool(
        principal.kind == "iam_user"
        and principal.programmatic_only
        and principal.access_keys
    )
