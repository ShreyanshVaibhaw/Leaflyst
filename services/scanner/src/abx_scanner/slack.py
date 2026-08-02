"""Read-only Slack Enterprise Grid app inventory.

Blueprint 2.3 records the platform limit: app inventory requires Enterprise
Grid admin APIs. A workspace on a lower tier cannot be scanned at all, and the
product must say so BEFORE someone connects, not after a failed scan. So the
tier check is its own step with its own typed outcome, rather than an
exception surfacing as a generic failure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from abx_scanner.slack_client import NOT_ENTERPRISE_ERRORS, SlackClient, SlackError

ENTERPRISE_ID = re.compile(r"^E[A-Z0-9]{8,}$")


@dataclass(frozen=True)
class SlackApp:
    app_id: str
    name: str
    scopes: tuple[str, ...]
    team_id: str
    installed_at: datetime | None
    restricted: bool

    @property
    def fingerprint(self) -> str:
        # An app id is a public identifier, never a token value.
        return f"slackapp:{self.app_id}"

    @property
    def write_scopes(self) -> tuple[str, ...]:
        return tuple(
            scope for scope in self.scopes
            if not scope.endswith(":read") and scope not in ("identity.basic",)
        )


@dataclass
class SlackScanResult:
    enterprise_id: str
    apps: list[SlackApp]
    api_calls: int
    notes: list[str] = field(default_factory=list)


class SlackTierUnavailable(RuntimeError):
    """The workspace is not on Enterprise Grid, so app inventory is impossible.

    A distinct type because this is a product-surface fact to disclose, not a
    transient failure to retry.
    """


def _dt(value: object) -> datetime | None:
    """Slack timestamps are unix seconds."""
    if not isinstance(value, (int, float, str)) or value in ("", 0):
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, TypeError, OSError):
        return None


def check_enterprise_tier(client: SlackClient) -> str:
    """Confirm Enterprise Grid before attempting any inventory call.

    Returns the enterprise id. Raises SlackTierUnavailable when the token's
    workspace cannot support admin app inventory at all.
    """
    try:
        identity = client.call("auth.test")
    except SlackError as exc:
        if exc.slack_error in NOT_ENTERPRISE_ERRORS:
            raise SlackTierUnavailable(
                "Slack app inventory requires Enterprise Grid; this workspace is on a "
                "plan that does not expose the admin APIs."
            ) from exc
        raise
    enterprise_id = str(identity.get("enterprise_id") or "")
    if not enterprise_id:
        raise SlackTierUnavailable(
            "Slack app inventory requires Enterprise Grid; this token is not scoped "
            "to an enterprise organization."
        )
    return enterprise_id


def _paged(client: SlackClient, method: str, key: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = ""
    while True:
        params = {"limit": "200"}
        if cursor:
            params["cursor"] = cursor
        page = client.call(method, params)
        values = page.get(key, [])
        if isinstance(values, list):
            items.extend(value for value in values if isinstance(value, dict))
        metadata = page.get("response_metadata")
        cursor = str(metadata.get("next_cursor", "")) if isinstance(metadata, dict) else ""
        if not cursor:
            return items


def _apps(entries: list[dict[str, Any]], restricted: bool) -> list[SlackApp]:
    out: list[SlackApp] = []
    for entry in entries:
        app = entry.get("app")
        if not isinstance(app, dict) or not app.get("id"):
            continue
        scopes = app.get("scopes", [])
        out.append(SlackApp(
            app_id=str(app["id"]),
            name=str(app.get("name") or ""),
            scopes=tuple(
                str(scope.get("name", scope)) if isinstance(scope, dict) else str(scope)
                for scope in (scopes if isinstance(scopes, list) else [])
            ),
            team_id=str(entry.get("team_id") or entry.get("scope") or ""),
            installed_at=_dt(entry.get("date_updated")),
            restricted=restricted,
        ))
    return out


def enumerate_enterprise(client: SlackClient) -> SlackScanResult:
    enterprise_id = check_enterprise_tier(client)
    approved = _apps(_paged(client, "admin.apps.approved.list", "approved_apps"), False)
    restricted = _apps(_paged(client, "admin.apps.restricted.list", "restricted_apps"), True)
    return SlackScanResult(
        enterprise_id=enterprise_id,
        apps=approved + restricted,
        api_calls=client.counter.count,
        notes=[
            "Slack app inventory requires Enterprise Grid admin APIs; workspaces on "
            "lower plans cannot be enumerated by any API.",
            "Slack does not expose a last-used timestamp for installed apps; approval "
            "state and granted scopes are reported without claiming usage freshness.",
        ],
    )
