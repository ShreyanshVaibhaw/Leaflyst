"""Read-only Google Workspace and Slack Enterprise Grid enumeration.

Both providers exist mainly to test one thing each that the earlier scanners
did not have to face:

- Workspace has NO last-used field, so freshness is derived from an audit log
  with a retention window. The tests pin that an unreadable log degrades to
  "unknown" and never to "unused" - telling someone a live grant is dormant is
  how you get a business-critical integration revoked.
- Slack is method-name addressed rather than verb addressed, so an HTTP-verb
  check proves nothing. The guard is an allowlist of read-only method names.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from abx_scanner.readonly import ReadOnlyViolation
from abx_scanner.slack import SlackTierUnavailable, enumerate_enterprise
from abx_scanner.slack_client import Response as SlackResponse
from abx_scanner.slack_client import SlackClient, SlackError
from abx_scanner.workspace import enumerate_domain
from abx_scanner.workspace_client import Response, WorkspaceClient
from conftest import requires_pg

DOMAIN = "example.com"
NOW = datetime.now(UTC)
CLIENT_ID = "1234567890.apps.googleusercontent.com"
DORMANT_CLIENT_ID = "9999999999.apps.googleusercontent.com"


# -- Google Workspace ---------------------------------------------------------

def workspace_opener(*, reports_ok: bool = True, seen: list[str] | None = None):
    def open_url(url: str) -> Response:
        if seen is not None:
            seen.append(url)
        if "/reports/" in url:
            if not reports_ok:
                return Response(status=403, body=b'{"error":"insufficient scope"}')
            body = {"items": [{
                "actor": {"email": "ana@example.com"},
                "id": {"time": (NOW - timedelta(days=3)).isoformat()},
                "events": [{"parameters": [{"name": "client_id", "value": CLIENT_ID}]}],
            }]}
        elif "/tokens" in url:
            body = {"items": [
                {"clientId": CLIENT_ID, "displayText": "Deploy Bot",
                 "scopes": ["https://www.googleapis.com/auth/drive"], "nativeApp": False},
                {"clientId": DORMANT_CLIENT_ID, "displayText": "Old Reporter",
                 "scopes": ["https://www.googleapis.com/auth/spreadsheets"],
                 "nativeApp": False},
            ]}
        elif "/users" in url:
            body = {"users": [{"primaryEmail": "ana@example.com"}]}
        else:
            return Response(status=404, body=b"{}")
        return Response(status=200, body=json.dumps(body).encode())

    return open_url


def test_workspace_client_exposes_no_write_path() -> None:
    client = WorkspaceClient(opener=workspace_opener())
    assert {n for n in dir(client) if not n.startswith("_")} == {"opener", "counter", "get"}
    with pytest.raises(ReadOnlyViolation):
        client._request("POST", "/admin/directory/v1/users")


def test_workspace_rejects_undeclared_paths() -> None:
    client = WorkspaceClient(opener=workspace_opener())
    with pytest.raises(ValueError):
        client.get("/admin/datatransfer/v1/transfers")


def test_workspace_derives_freshness_from_the_audit_log() -> None:
    result = enumerate_domain(WorkspaceClient(opener=workspace_opener()), DOMAIN)
    by_client = {grant.client_id: grant for grant in result.grants}
    assert result.usage_observable is True
    assert by_client[CLIENT_ID].last_used_at is not None
    assert by_client[CLIENT_ID].dormant(NOW) is False
    assert by_client[DORMANT_CLIENT_ID].dormant(NOW) is True


def test_unreadable_audit_log_means_unknown_not_unused() -> None:
    """The failure that matters. Reporting a live grant as dormant is how a
    business-critical integration gets revoked on our advice."""
    result = enumerate_domain(
        WorkspaceClient(opener=workspace_opener(reports_ok=False)), DOMAIN
    )
    assert result.usage_observable is False
    assert all(grant.dormant(NOW) is False for grant in result.grants)
    assert any("UNKNOWN rather than absent" in note for note in result.notes)


def test_workspace_states_its_retention_window() -> None:
    notes = " ".join(enumerate_domain(WorkspaceClient(opener=workspace_opener()), DOMAIN).notes)
    assert "not the same as never used" in notes


def test_workspace_flags_sensitive_scopes() -> None:
    result = enumerate_domain(WorkspaceClient(opener=workspace_opener()), DOMAIN)
    grant = next(g for g in result.grants if g.client_id == CLIENT_ID)
    assert grant.sensitive_scopes == ("https://www.googleapis.com/auth/drive",)


def test_workspace_rejects_a_bad_domain_before_calling() -> None:
    seen: list[str] = []
    with pytest.raises(ValueError):
        enumerate_domain(WorkspaceClient(opener=workspace_opener(seen=seen)), "not a domain")
    assert seen == []


def test_workspace_fingerprints_never_contain_a_token() -> None:
    result = enumerate_domain(WorkspaceClient(opener=workspace_opener()), DOMAIN)
    assert all(grant.fingerprint.startswith("gwsgrant:") for grant in result.grants)


# -- Slack --------------------------------------------------------------------

def slack_opener(*, enterprise: bool = True, error: str | None = None):
    def open_url(url: str, _token: str) -> SlackResponse:
        if "auth.test" in url:
            if error:
                body = {"ok": False, "error": error}
            elif enterprise:
                body = {"ok": True, "enterprise_id": "E12345678", "team_id": "T1"}
            else:
                body = {"ok": True, "team_id": "T1"}
        elif "admin.apps.approved.list" in url:
            body = {"ok": True, "approved_apps": [{
                "app": {"id": "A1", "name": "Deploy Bot",
                        "scopes": [{"name": "chat:write"}, {"name": "channels:read"}]},
                "team_id": "T1", "date_updated": 1700000000,
            }]}
        elif "admin.apps.restricted.list" in url:
            body = {"ok": True, "restricted_apps": [{
                "app": {"id": "A2", "name": "Sketchy", "scopes": [{"name": "files:write"}]},
                "team_id": "T1", "date_updated": 1700000000,
            }]}
        else:
            body = {"ok": False, "error": "unknown_method"}
        return SlackResponse(status=200, body=json.dumps(body).encode())

    return open_url


def test_slack_allows_only_read_only_methods() -> None:
    """Slack is method-addressed, so the verb proves nothing and the allowlist
    is the actual guard."""
    client = SlackClient("xoxb-test", opener=slack_opener())
    for method in ("admin.apps.approve", "admin.apps.restrict", "chat.postMessage",
                   "admin.users.remove", "conversations.create"):
        with pytest.raises(ReadOnlyViolation):
            client.call(method)


def test_slack_enumerates_approved_and_restricted_apps() -> None:
    result = enumerate_enterprise(SlackClient("xoxb-test", opener=slack_opener()))
    apps = {app.app_id: app for app in result.apps}
    assert set(apps) == {"A1", "A2"}
    assert apps["A1"].restricted is False
    assert apps["A2"].restricted is True
    assert apps["A1"].write_scopes == ("chat:write",)


def test_slack_non_enterprise_is_a_typed_disclosure_not_a_crash() -> None:
    """Blueprint 2.3: the tier requirement must be stated, and it has to be
    distinguishable from a transient failure so the UI can say so before a
    connect attempt rather than after."""
    with pytest.raises(SlackTierUnavailable) as exc:
        enumerate_enterprise(SlackClient("xoxb-test", opener=slack_opener(enterprise=False)))
    assert "Enterprise Grid" in str(exc.value)

    with pytest.raises(SlackTierUnavailable):
        enumerate_enterprise(
            SlackClient("xoxb-test", opener=slack_opener(error="not_an_enterprise"))
        )


def test_slack_other_errors_are_not_swallowed_as_tier_problems() -> None:
    with pytest.raises(SlackError):
        enumerate_enterprise(
            SlackClient("xoxb-test", opener=slack_opener(error="invalid_auth"))
        )


def test_slack_tier_is_checked_before_any_inventory_call() -> None:
    calls: list[str] = []

    def counting(url: str, token: str):
        calls.append(url)
        return slack_opener(enterprise=False)(url, token)

    with pytest.raises(SlackTierUnavailable):
        enumerate_enterprise(SlackClient("xoxb-test", opener=counting))
    assert all("admin.apps" not in url for url in calls)


def test_slack_notes_disclose_both_platform_limits() -> None:
    notes = " ".join(enumerate_enterprise(SlackClient("x", opener=slack_opener())).notes)
    assert "Enterprise Grid" in notes
    assert "last-used" in notes


# -- persistence --------------------------------------------------------------

@requires_pg
def test_workspace_scan_persists_and_is_idempotent(tenant) -> None:
    from abx_scanner.db import connect
    from abx_scanner.scan import run_workspace_scan

    with connect() as conn:
        first = run_workspace_scan(
            tenant, DOMAIN, WorkspaceClient(opener=workspace_opener()), conn=conn
        )
        before = conn.execute(
            "SELECT count(*) FROM credentials WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]
        run_workspace_scan(
            tenant, DOMAIN, WorkspaceClient(opener=workspace_opener()), conn=conn
        )
        after = conn.execute(
            "SELECT count(*) FROM credentials WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]
    assert first.credentials == 2
    assert before == after == 2


@requires_pg
def test_slack_scan_persists_and_is_idempotent(tenant) -> None:
    from abx_scanner.db import connect
    from abx_scanner.scan import run_slack_scan

    with connect() as conn:
        first = run_slack_scan(tenant, SlackClient("x", opener=slack_opener()), conn=conn)
        before = conn.execute(
            "SELECT count(*) FROM credentials WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]
        run_slack_scan(tenant, SlackClient("x", opener=slack_opener()), conn=conn)
        after = conn.execute(
            "SELECT count(*) FROM credentials WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]
        fingerprints = [
            row[0] for row in conn.execute(
                "SELECT fingerprint FROM credentials WHERE tenant_id = %s", (tenant,)
            ).fetchall()
        ]
    assert first.credentials == 2
    assert before == after == 2
    assert all(value.startswith("slackapp:") for value in fingerprints)


@requires_pg
def test_write_scoped_apps_are_flagged(tenant) -> None:
    from abx_scanner.db import connect
    from abx_scanner.scan import run_slack_scan

    with connect() as conn:
        run_slack_scan(tenant, SlackClient("x", opener=slack_opener()), conn=conn)
        rows = conn.execute(
            "SELECT natural_key FROM findings WHERE tenant_id = %s "
            "AND finding_type = 'over_privileged'",
            (tenant,),
        ).fetchall()
    assert {str(row[0]) for row in rows} == {
        "slack:overpriv:slackapp:A1", "slack:overpriv:slackapp:A2",
    }
