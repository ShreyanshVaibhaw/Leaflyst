"""Read-only Google Workspace OAuth token and delegation enumeration.

Blueprint 2.3 records the gap that shapes this whole module: the Directory API
lists which OAuth tokens a user has issued, but carries NO last-used
timestamp. Reporting a blank freshness column, or substituting token age for
usage, would both be worse than useless on a screen whose job is to tell
someone which grants are dead.

So freshness is DERIVED, by correlating the token audit log from the Reports
API. That correlation is explicit about its own limits: the audit log has a
retention window (180 days by default), so "not seen" means "not used within
the window we can see", never "never used". The distinction is carried in the
data rather than left to the reader.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from abx_scanner.workspace_client import WorkspaceClient

DOMAIN = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)

# Default Admin-console audit retention for the token application.
AUDIT_WINDOW_DAYS = 180

# Scopes that grant broad read or write over user content. Anything here on a
# third-party grant is worth surfacing.
SENSITIVE_SCOPE_MARKERS = (
    "/auth/drive",
    "/auth/gmail",
    "/auth/spreadsheets",
    "/auth/documents",
    "/auth/admin.directory",
    "/auth/cloud-platform",
    "/auth/calendar",
)


@dataclass(frozen=True)
class WorkspaceGrant:
    user_email: str
    client_id: str
    display_text: str
    scopes: tuple[str, ...]
    native_app: bool
    anonymous: bool
    last_used_at: datetime | None
    usage_observable: bool

    @property
    def fingerprint(self) -> str:
        # The client id is a public application identifier, not a secret.
        return f"gwsgrant:{self.user_email}:{self.client_id}"

    @property
    def sensitive_scopes(self) -> tuple[str, ...]:
        return tuple(
            scope for scope in self.scopes
            if any(marker in scope for marker in SENSITIVE_SCOPE_MARKERS)
        )

    def dormant(self, now: datetime) -> bool:
        """No observed use inside the audit window.

        False when usage is not observable at all: an unknown answer must not
        read as a confident 'unused'.
        """
        return self.usage_observable and self.last_used_at is None


@dataclass
class WorkspaceScanResult:
    domain: str
    grants: list[WorkspaceGrant]
    api_calls: int
    usage_observable: bool
    notes: list[str] = field(default_factory=list)


def _dt(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _pages(
    client: WorkspaceClient, path: str, item_key: str, params: dict[str, str]
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = ""
    while True:
        page_params = dict(params)
        if token:
            page_params["pageToken"] = token
        page = client.get(path, page_params)
        values = page.get(item_key, [])
        if isinstance(values, list):
            items.extend(value for value in values if isinstance(value, dict))
        token = str(page.get("nextPageToken", ""))
        if not token:
            return items


def _last_used(
    client: WorkspaceClient,
) -> tuple[dict[tuple[str, str], datetime], bool]:
    """Most recent observed use per (user, client id), from the token audit log.

    Returns (index, observable). observable is False when the Reports API is
    unavailable to this scan identity, which must degrade to "unknown" rather
    than to "unused".
    """
    start = (datetime.now(UTC) - timedelta(days=AUDIT_WINDOW_DAYS)).isoformat()
    try:
        activities = _pages(
            client,
            "/admin/reports/v1/activity/users/all/applications/token",
            "items",
            {"maxResults": "1000", "startTime": start},
        )
    except Exception:  # noqa: BLE001 - absence of the log is a coverage fact
        return {}, False

    index: dict[tuple[str, str], datetime] = {}
    for activity in activities:
        actor = activity.get("actor")
        email = str(actor.get("email", "")) if isinstance(actor, dict) else ""
        marker = activity.get("id")
        when = _dt(marker.get("time") if isinstance(marker, dict) else None)
        if not email or when is None:
            continue
        for event in activity.get("events", []) or []:
            if not isinstance(event, dict):
                continue
            for parameter in event.get("parameters", []) or []:
                if not isinstance(parameter, dict) or parameter.get("name") != "client_id":
                    continue
                key = (email.lower(), str(parameter.get("value", "")))
                if key[1] and (key not in index or index[key] < when):
                    index[key] = when
    return index, True


def enumerate_domain(client: WorkspaceClient, domain: str) -> WorkspaceScanResult:
    if not DOMAIN.fullmatch(domain):
        raise ValueError("invalid Google Workspace domain")

    users = _pages(
        client,
        "/admin/directory/v1/users",
        "users",
        {"domain": domain, "maxResults": "500", "projection": "basic"},
    )
    usage, observable = _last_used(client)

    grants: list[WorkspaceGrant] = []
    for user in users:
        email = str(user.get("primaryEmail", ""))
        if not email:
            continue
        tokens = client.get(
            f"/admin/directory/v1/users/{quote(email, safe='@')}/tokens"
        ).get("items", [])
        for token in tokens if isinstance(tokens, list) else []:
            if not isinstance(token, dict) or not token.get("clientId"):
                continue
            client_id = str(token["clientId"])
            grants.append(WorkspaceGrant(
                user_email=email,
                client_id=client_id,
                display_text=str(token.get("displayText") or ""),
                scopes=tuple(
                    str(scope) for scope in token.get("scopes", []) or []
                ),
                native_app=bool(token.get("nativeApp", False)),
                anonymous=bool(token.get("anonymous", False)),
                last_used_at=usage.get((email.lower(), client_id)),
                usage_observable=observable,
            ))

    notes = [
        "The Directory API exposes no last-used timestamp for OAuth tokens; "
        "freshness is derived by correlating the Reports token audit log.",
    ]
    if observable:
        notes.append(
            f"Usage is derived from the last {AUDIT_WINDOW_DAYS} days of audit log. "
            "A grant with no observed use was not used within that window, which is "
            "not the same as never used."
        )
    else:
        notes.append(
            "The Reports audit log was not readable by this scan identity, so token "
            "usage is UNKNOWN rather than absent. Grant admin.reports.audit.readonly "
            "to enable freshness."
        )
    return WorkspaceScanResult(
        domain=domain,
        grants=grants,
        api_calls=client.counter.count,
        usage_observable=observable,
        notes=notes,
    )
