"""GitHub enumeration (read-only) into intermediate dataclasses.

Covers what an org admin can see via a GitHub App installation token:
- org fine-grained PATs (+ last-used, permissions, repo reach),
- deploy keys per repo (+ last-used, read/write),
- App installations (+ granted permissions).

Disclosed gap (blueprint 2.3): classic PATs are NOT enumerable org-wide by any
API; the scan reports this rather than pretending coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from abx_scanner.gh_client import GitHubClient


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class GitHubCredential:
    kind: str  # fine_grained_pat | deploy_key | app_installation
    fingerprint: str  # non-secret id, e.g. "pat:123", "deploykey:org/repo:45"
    owner_login: str
    owner_kind: str  # gh_user | gh_app
    created_at: datetime | None
    last_used_at: datetime | None
    # permission scope -> access ("read"|"write"|"admin")
    permissions: dict[str, str] = field(default_factory=dict)
    reachable_repos: list[str] = field(default_factory=list)


@dataclass
class GitHubScanResult:
    org: str
    credentials: list[GitHubCredential]
    api_calls: int
    notes: list[str] = field(default_factory=list)


_ACCESS_RANK = {"read": 0, "write": 1, "admin": 2}


def _normalize_permissions(perms: dict[str, dict[str, str]]) -> dict[str, str]:
    """GitHub returns {category: {perm: access}}; flatten to {perm: access}."""
    out: dict[str, str] = {}
    for _category, entries in (perms or {}).items():
        if isinstance(entries, dict):
            for perm, access in entries.items():
                out[perm] = str(access)
    return out


def enumerate_org(client: GitHubClient, org: str) -> GitHubScanResult:
    credentials: list[GitHubCredential] = []
    notes = [
        "Classic personal access tokens cannot be enumerated org-wide by any "
        "GitHub API; enable the org policy blocking classic PATs for full coverage."
    ]

    # Fine-grained PATs (App-only endpoint).
    for pat in client.paginate(f"/orgs/{org}/personal-access-tokens"):
        pat_id = pat["id"]
        repos = client.get(f"/orgs/{org}/personal-access-tokens/{pat_id}/repositories") or []
        credentials.append(
            GitHubCredential(
                kind="fine_grained_pat",
                fingerprint=f"pat:{pat_id}",
                owner_login=pat.get("owner", {}).get("login", "unknown"),
                owner_kind="gh_user",
                created_at=_dt(pat.get("access_granted_at")),
                last_used_at=_dt(pat.get("token_last_used_at")),
                permissions=_normalize_permissions(pat.get("permissions", {})),
                reachable_repos=[f"gh:repo:{org}/{r['name']}" for r in repos],
            )
        )

    # Deploy keys per repo.
    for repo in client.paginate(f"/orgs/{org}/repos"):
        repo_name = repo["name"]
        for key in client.get(f"/repos/{org}/{repo_name}/keys") or []:
            access = "read" if key.get("read_only", True) else "write"
            credentials.append(
                GitHubCredential(
                    kind="deploy_key",
                    fingerprint=f"deploykey:{org}/{repo_name}:{key['id']}",
                    owner_login=f"{org}/{repo_name}",
                    owner_kind="gh_user",
                    created_at=_dt(key.get("created_at")),
                    last_used_at=_dt(key.get("last_used")),
                    permissions={"contents": access},
                    reachable_repos=[f"gh:repo:{org}/{repo_name}"],
                )
            )

    # App installations.
    for inst in client.paginate(f"/orgs/{org}/installations", item_key="installations"):
        credentials.append(
            GitHubCredential(
                kind="app_installation",
                fingerprint=f"appinstall:{inst['id']}",
                owner_login=inst.get("app_slug", "unknown"),
                owner_kind="gh_app",
                created_at=_dt(inst.get("created_at")),
                last_used_at=_dt(inst.get("updated_at")),
                permissions=_normalize_permissions(
                    {"install": inst.get("permissions", {})}
                ),
                reachable_repos=[],
            )
        )

    return GitHubScanResult(
        org=org, credentials=credentials, api_calls=client.counter.count, notes=notes
    )
