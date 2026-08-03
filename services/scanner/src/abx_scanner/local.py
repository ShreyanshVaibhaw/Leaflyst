"""Customer-hosted AWS scan that uploads findings only."""

from __future__ import annotations

import argparse
import json
import os
import urllib.request
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from abx_scanner.aws import AwsScanResult, enumerate_account
from abx_scanner.policy import is_admin_wildcard, is_destructive, normalize_resource


def build_upload(result: AwsScanResult) -> dict[str, Any]:
    output: list[dict[str, Any]] = []
    now = datetime.now(UTC)
    for principal in result.principals:
        grants = [grant for policy in principal.policies for grant in policy.grants]
        resources = sorted({normalize_resource(grant.resource)[0] for grant in grants})
        destructive = sorted({grant.action for grant in grants if is_destructive(grant.action)})
        normalized_grants = []
        for grant in grants:
            identifier, _provider, kind, environment = normalize_resource(grant.resource)
            access = (
                "admin" if is_admin_wildcard(grant.action, grant.resource)
                else "write" if is_destructive(grant.action) else "read"
            )
            normalized_grants.append({
                "action": grant.action, "resource": identifier, "kind": kind,
                "environment": environment, "access": access,
            })
        broad = any(is_admin_wildcard(grant.action, grant.resource) for grant in grants)
        for key in principal.access_keys:
            age_days = (now - _aware(key.created_at)).days if key.created_at else None
            unused_days = (now - _aware(key.last_used_at)).days if key.last_used_at else None
            evidence = {
                "age_days": age_days,
                "never_used": key.last_used_at is None,
                "reach_count": len(resources),
                "reachable_resources": resources[:100],
                "destructive_actions": destructive[:100],
                "grants": normalized_grants[:1000],
            }
            common = {
                "provider": "aws",
                "credential_kind": "access_key",
                "fingerprint": key.access_key_id,
                "owner": principal.arn,
                "evidence": evidence,
            }
            if key.last_used_at is None or (unused_days is not None and unused_days > 30):
                output.append(
                    {
                        **common,
                        "natural_key": f"aws:orphaned:{key.access_key_id}",
                        "finding_type": "orphaned_credential",
                        "severity": "high" if destructive else "medium",
                        "remediation": "Deactivate and remove the unused access key.",
                    }
                )
            if broad:
                output.append(
                    {
                        **common,
                        "natural_key": f"aws:overpriv:{key.access_key_id}",
                        "finding_type": "over_privileged",
                        "severity": "critical",
                        "remediation": "Replace wildcard administration with least privilege.",
                    }
                )
            if age_days is not None and age_days > 90:
                output.append(
                    {
                        **common,
                        "natural_key": f"aws:stale:{key.access_key_id}",
                        "finding_type": "stale_authorization",
                        "severity": "medium",
                        "remediation": "Rotate this access key.",
                    }
                )
            output.append(
                {
                    **common,
                    "natural_key": f"aws:blast:{key.access_key_id}",
                    "finding_type": "blast_radius",
                    "severity": "info",
                    "remediation": "Review the resources reachable by this credential.",
                }
            )
    return {"scope": result.account_id, "api_calls": result.api_calls, "findings": output}


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def upload_findings(api_url: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
    parsed = urlparse(api_url)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("scan uploads require HTTPS (HTTP is allowed only on loopback)")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("invalid scan upload URL")
    request = urllib.request.Request(  # noqa: S310 - operator-configured destination, never a caller-supplied URL
        f"{api_url.rstrip('/')}/v1/scans/local",
        method="POST",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=30) as response:
        return json.loads(response.read())  # type: ignore[no-any-return]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a read-only AWS scan locally")
    parser.add_argument("--api-url", help="Leaflyst API URL")
    parser.add_argument("--output", action="store_true", help="print findings JSON")
    args = parser.parse_args()
    body = build_upload(enumerate_account())
    if args.output or not args.api_url:
        print(json.dumps(body, indent=2, default=str))
        return 0
    token = os.environ.get("ABX_SCAN_TOKEN")
    if not token:
        parser.error("ABX_SCAN_TOKEN is required for upload")
    result = upload_findings(args.api_url, token, body)
    print(f"uploaded {result['findings']} findings from read-only local scan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
