"""GitHub scanner tests with a mocked REST layer (no network).

Seeds an org with a stale over-scoped PAT, a writable deploy key, an orphaned
App installation, and a tidy read-only PAT, then asserts findings and the
classic-PAT visibility-gap note.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from abx_scanner.db import connect
from abx_scanner.gh_client import GitHubClient, Response
from abx_scanner.scan import run_github_scan
from conftest import requires_pg

pytestmark = requires_pg

ORG = "acme"


def _iso(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


# Canned API responses keyed by path.
def _routes() -> dict[str, object]:
    return {
        f"/orgs/{ORG}/personal-access-tokens": [
            {
                "id": 101,
                "owner": {"login": "svc-deploy-bot"},
                "access_granted_at": _iso(200),  # stale (>90d)
                "token_last_used_at": _iso(120),  # orphaned (>30d)
                "permissions": {"repository": {"contents": "write", "administration": "admin"}},
            },
            {
                "id": 102,
                "owner": {"login": "alice"},
                "access_granted_at": _iso(10),
                "token_last_used_at": _iso(1),
                "permissions": {"repository": {"metadata": "read"}},
            },
            {
                "id": 103,
                "owner": {"login": "svc-deploy-bot"},
                "access_granted_at": _iso(5),
                "token_last_used_at": _iso(1),
                "permissions": {"repository": {"metadata": "read"}},
            },
        ],
        f"/orgs/{ORG}/personal-access-tokens/101/repositories": [
            {"name": "prod-api"}, {"name": "billing"},
        ],
        f"/orgs/{ORG}/personal-access-tokens/102/repositories": [{"name": "docs"}],
        f"/orgs/{ORG}/personal-access-tokens/103/repositories": [{"name": "docs"}],
        f"/orgs/{ORG}/repos": [{"name": "prod-api"}],
        f"/repos/{ORG}/prod-api/keys": [
            {"id": 55, "title": "ci", "read_only": False,  # writable deploy key
             "created_at": _iso(5), "last_used": _iso(2)},
        ],
        f"/orgs/{ORG}/installations": {
            "installations": [
                {"id": 900, "app_slug": "renovate", "created_at": _iso(300),
                 "updated_at": _iso(100),  # orphaned app install
                 "permissions": {"contents": "write"}},
            ]
        },
    }


def make_client() -> GitHubClient:
    routes = _routes()

    def opener(req) -> Response:
        path = req.full_url.replace("https://api.github.com", "")
        if path not in routes:
            return Response(404, {}, b"")
        return Response(200, {}, json.dumps(routes[path]).encode())

    return GitHubClient(token="fake", opener=opener)


def _findings(tenant_id: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT finding_type, natural_key, severity, evidence FROM findings "
            "WHERE tenant_id = %s ORDER BY finding_type, natural_key",
            (tenant_id,),
        ).fetchall()
    return [{"type": r[0], "key": r[1], "severity": r[2], "evidence": r[3]} for r in rows]


def test_github_scan_flags_over_scoped_pat(tenant: str) -> None:
    summary = run_github_scan(tenant, ORG, make_client())
    assert summary.credentials == 5  # 3 PATs + 1 deploy key + 1 app install
    assert summary.api_calls > 0

    findings = _findings(tenant)
    overpriv = [f for f in findings if f["type"] == "over_privileged"]
    # The svc-deploy-bot PAT has administration:admin -> critical.
    pat = next(f for f in overpriv if f["evidence"]["fingerprint"] == "pat:101")
    assert pat["severity"] == "critical"
    assert pat["evidence"]["reach_count"] >= 1

    # The read-only PAT (alice) is NOT over-privileged.
    assert not any(f["evidence"]["fingerprint"] == "pat:102" for f in overpriv)
    # Same owner as pat:101, but permissions must not bleed across credentials.
    assert not any(f["evidence"]["fingerprint"] == "pat:103" for f in overpriv)

    # Stale + orphaned both fired for the old PAT.
    keys = {f["key"] for f in findings}
    assert "github:stale:pat:101" in keys
    assert "github:orphaned:pat:101" in keys


def test_github_scan_flags_writable_deploy_key(tenant: str) -> None:
    run_github_scan(tenant, ORG, make_client())
    overpriv = [f for f in _findings(tenant) if f["type"] == "over_privileged"]
    key = next(
        (f for f in overpriv if f["evidence"]["fingerprint"].startswith("deploykey:")), None
    )
    assert key is not None  # writable deploy key is over-privileged (write access)
    assert key["severity"] == "high"


def test_github_scan_is_idempotent(tenant: str) -> None:
    run_github_scan(tenant, ORG, make_client())
    first = _findings(tenant)
    with connect() as conn:
        perms1 = conn.execute(
            "SELECT count(*) FROM permissions WHERE tenant_id = %s AND provider='github'",
            (tenant,),
        ).fetchone()[0]
    run_github_scan(tenant, ORG, make_client())
    second = _findings(tenant)
    with connect() as conn:
        perms2 = conn.execute(
            "SELECT count(*) FROM permissions WHERE tenant_id = %s AND provider='github'",
            (tenant,),
        ).fetchone()[0]
    assert {f["key"] for f in first} == {f["key"] for f in second}
    assert perms1 == perms2


def test_classic_pat_gap_disclosed() -> None:
    from abx_scanner.github import enumerate_org

    result = enumerate_org(make_client(), ORG)
    assert any("classic" in n.lower() for n in result.notes)


def test_read_only_enforced() -> None:
    from abx_scanner.gh_client import GitHubClient
    from abx_scanner.readonly import ReadOnlyViolation

    client = GitHubClient(token="x", opener=lambda r: Response(200, {}, b"[]"))
    with pytest.raises(ReadOnlyViolation):
        client._request("DELETE", f"/orgs/{ORG}/personal-access-tokens/1")
