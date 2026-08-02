"""Impact-first credential containment with isolated write-only adapters."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

import boto3
from abx_schemas import IngestEvent
from fastapi import APIRouter, Depends, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from abx_api.identifiers import ResourceId
from abx_api.ingest import ingest_events
from abx_api.rbac import require_revoke
from abx_api.settings import settings
from abx_api.store import ch_client, pg_pool

router = APIRouter(prefix="/v1/revocation", dependencies=[Depends(require_revoke)])


class ImpactPreview(BaseModel):
    credential_id: str
    provider: str
    kind: str
    fingerprint: str
    status: str
    cold: bool
    one_click: bool
    write_credential_configured: bool
    last_used_at: str | None
    events_last_30d: int
    last_recorded_at: str | None
    agent_consumers: list[str]
    reachable_resources: list[str]
    next_action: str
    guided_commands: list[str]


class RevokeRequest(BaseModel):
    confirmation: str
    action: Literal["deactivate", "delete", "revoke"]


class RevokeResult(BaseModel):
    status: str
    action: str
    credential_status: str


class RevokeAdapter(Protocol):
    def execute(self, action: str, credential: dict[str, Any]) -> None: ...


class AwsRevokeAdapter:
    """Write-only IAM adapter: intentionally exposes no list/get methods."""

    def __init__(self) -> None:
        self.client = boto3.client(
            "iam", aws_access_key_id=settings.aws_revoke_access_key_id,
            aws_secret_access_key=settings.aws_revoke_secret_access_key,
            aws_session_token=settings.aws_revoke_session_token or None,
        )

    def execute(self, action: str, credential: dict[str, Any]) -> None:
        arguments = {
            "UserName": credential["owner"],
            "AccessKeyId": credential["fingerprint"],
        }
        if action == "deactivate":
            self.client.update_access_key(Status="Inactive", **arguments)
        elif action == "delete":
            self.client.delete_access_key(**arguments)
        else:
            raise ValueError("unsupported AWS revocation action")


class GitHubRevokeAdapter:
    """Write-only GitHub adapter using a separately supplied write token."""

    def execute(self, action: str, credential: dict[str, Any]) -> None:
        if action != "revoke":
            raise ValueError("GitHub credentials support revoke only")
        fingerprint = credential["fingerprint"]
        if fingerprint.startswith("pat:"):
            path = f"/orgs/{credential['org']}/personal-access-tokens/{fingerprint[4:]}"
            method, body = "POST", {"action": "revoke"}
        elif fingerprint.startswith("deploykey:"):
            identity = fingerprint.removeprefix("deploykey:")
            repo, key_id = identity.rsplit(":", 1)
            path = f"/repos/{repo}/keys/{key_id}"
            method, body = "DELETE", None
        else:
            raise ValueError("unsupported GitHub credential kind")
        request = urllib.request.Request(  # noqa: S310 - fixed GitHub HTTPS root
            "https://api.github.com" + path, method=method,
            data=json.dumps(body).encode() if body else None,
            headers={
                "Authorization": f"Bearer {settings.github_revoke_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "leaflyst-revocation",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                if response.status not in {202, 204}:
                    raise RuntimeError(f"GitHub returned {response.status}")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GitHub revocation failed ({exc.code})") from exc


def _credential(tenant_id: str, credential_id: str) -> dict[str, Any]:
    with pg_pool().connection() as conn:
        row = conn.execute(
            "SELECT c.id, c.provider, c.kind, c.fingerprint, c.status, c.last_used_at, "
            "p.external_id, ic.account_login FROM credentials c "
            "LEFT JOIN principals p ON p.id = c.owner_principal "
            "LEFT JOIN integration_connections ic ON ic.tenant_id = c.tenant_id "
            "AND ic.provider = c.provider AND ic.status = 'connected' "
            "WHERE c.tenant_id = %s AND c.id = %s LIMIT 1",
            (tenant_id, credential_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="credential not found")
    owner = (row[6] or "").rsplit("/", 1)[-1]
    return {
        "id": str(row[0]), "provider": row[1], "kind": row[2],
        "fingerprint": row[3], "status": row[4], "last_used_at": row[5],
        "owner": owner, "org": row[7] or "ORG",
    }


@router.get("/{credential_id}/impact", response_model=ImpactPreview)
def impact(tenant_id: str, credential_id: ResourceId) -> ImpactPreview:
    credential = _credential(tenant_id, credential_id)
    fingerprint = credential["fingerprint"]
    result = ch_client().query(
        "SELECT count() AS n, max(ts) AS last_seen FROM events "
        "WHERE tenant_id = %(tenant)s AND credential_ref = %(credential)s "
        "AND ts >= now() - INTERVAL 30 DAY",
        parameters={"tenant": tenant_id, "credential": fingerprint},
    )
    event_count, last_recorded = result.result_rows[0]
    with pg_pool().connection() as conn:
        agents = [row[0] for row in conn.execute(
            "SELECT a.name FROM agents a JOIN agent_holds_credential ahc ON ahc.agent_id=a.id "
            "WHERE a.tenant_id=%s AND ahc.credential_id=%s ORDER BY a.name",
            (tenant_id, credential_id),
        ).fetchall()]
        resources = [row[0] for row in conn.execute(
            "SELECT DISTINCT r.identifier FROM permissions p "
            "JOIN permission_reaches_resource pr ON pr.permission_id=p.id "
            "JOIN resources r ON r.id=pr.resource_id "
            "WHERE p.tenant_id=%s AND (p.credential_id=%s OR p.principal_id="
            "(SELECT owner_principal FROM credentials WHERE tenant_id=%s AND id=%s)) "
            "ORDER BY r.identifier",
            (tenant_id, credential_id, tenant_id, credential_id),
        ).fetchall()]
    cutoff = datetime.now(UTC) - timedelta(days=30)
    signals = [value for value in (credential["last_used_at"], last_recorded) if value]
    cold = not signals or all(
        value.replace(tzinfo=UTC) < cutoff if value.tzinfo is None else value < cutoff
        for value in signals
    )
    if credential["provider"] == "aws":
        configured = bool(
            settings.aws_revoke_access_key_id and settings.aws_revoke_secret_access_key
        )
    elif credential["provider"] == "github":
        configured = bool(settings.github_revoke_token)
    else:
        configured = False
    supported = credential["kind"] in {
        "access_key",
        "fine_grained_pat",
        "deploy_key",
    }
    commands = _guided_commands(credential)
    if credential["provider"] in {"aws", "gcp"}:
        next_action = "delete" if credential["status"] == "inactive" else "deactivate"
    else:
        next_action = "revoke"
    return ImpactPreview(
        credential_id=credential_id, provider=credential["provider"], kind=credential["kind"],
        fingerprint=fingerprint, status=credential["status"], cold=cold,
        one_click=cold and configured and supported,
        write_credential_configured=configured, last_used_at=(
            credential["last_used_at"].isoformat() if credential["last_used_at"] else None
        ), events_last_30d=int(event_count),
        last_recorded_at=last_recorded.isoformat() if last_recorded else None,
        agent_consumers=agents, reachable_resources=resources, next_action=next_action,
        guided_commands=commands,
    )


def _guided_commands(credential: dict[str, Any]) -> list[str]:
    fingerprint, owner = credential["fingerprint"], credential["owner"]
    if credential["provider"] == "aws":
        base = f"--user-name {owner} --access-key-id {fingerprint}"
        return [f"aws iam update-access-key {base} --status Inactive",
                f"aws iam delete-access-key {base}"]
    if credential["provider"] == "gcp" and fingerprint.startswith("gcpkey:"):
        key_id = fingerprint.removeprefix("gcpkey:")
        suffix = f"{key_id} --iam-account={owner} --project={credential['org']}"
        return [
            f"gcloud iam service-accounts keys disable {suffix}",
            f"gcloud iam service-accounts keys delete {suffix}",
        ]
    if fingerprint.startswith("pat:"):
        return [
            f"gh api --method POST /orgs/{credential['org']}/personal-access-tokens/"
            f"{fingerprint[4:]} -f action=revoke"
        ]
    if fingerprint.startswith("deploykey:"):
        repo, key_id = fingerprint.removeprefix("deploykey:").rsplit(":", 1)
        return [f"gh api --method DELETE /repos/{repo}/keys/{key_id}"]
    return ["Open the provider console and revoke this credential after rotating consumers."]


def adapter_for(provider: str) -> RevokeAdapter:
    if provider == "aws":
        return AwsRevokeAdapter()
    if provider == "github":
        return GitHubRevokeAdapter()
    raise ValueError(f"one-click revocation is not supported for provider {provider!r}")


@router.post("/{credential_id}", response_model=RevokeResult)
def revoke(tenant_id: str, credential_id: ResourceId, request: RevokeRequest) -> RevokeResult:
    preview = impact(tenant_id, credential_id)
    credential = _credential(tenant_id, credential_id)
    if request.confirmation != preview.fingerprint:
        raise HTTPException(status_code=422, detail="confirmation must match the fingerprint")
    if not preview.one_click:
        raise HTTPException(
            status_code=409,
            detail="warm or unconfigured credential requires guided revocation",
        )
    if request.action != preview.next_action:
        raise HTTPException(status_code=409, detail=f"next safe action is {preview.next_action}")
    status = "succeeded"
    try:
        adapter_for(preview.provider).execute(request.action, credential)
    except Exception as exc:
        status = "failed"
        _record_action(tenant_id, credential_id, preview.provider, request.action, status,
                       {"error_type": type(exc).__name__})
        _record_chain_event(
            tenant_id, preview, request.action, outcome="error",
            error_type=type(exc).__name__,
        )
        raise HTTPException(status_code=502, detail="provider revocation failed") from exc
    new_status = "inactive" if request.action == "deactivate" else "revoked"
    with pg_pool().connection() as conn:
        conn.execute(
            "UPDATE credentials SET status=%s WHERE tenant_id=%s AND id=%s",
            (new_status, tenant_id, credential_id),
        )
    _record_action(tenant_id, credential_id, preview.provider, request.action, status,
                   {"cold": preview.cold, "events_last_30d": preview.events_last_30d})
    _record_chain_event(tenant_id, preview, request.action)
    return RevokeResult(status=status, action=request.action, credential_status=new_status)


def _record_action(
    tenant_id: str, credential_id: str, provider: str, action: str,
    status: str, evidence: dict[str, object],
) -> None:
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO revocation_actions "
            "(tenant_id, credential_id, action, provider, status, evidence) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (tenant_id, credential_id, action, provider, status, Jsonb(evidence)),
        )


def _record_chain_event(
    tenant_id: str,
    preview: ImpactPreview,
    action: str,
    *,
    outcome: str = "success",
    error_type: str | None = None,
) -> None:
    event = IngestEvent.model_validate({
        "event_id": str(uuid.uuid4()), "agent_id": "abx-admin",
        "session_id": f"revocation:{uuid.uuid4()}", "seq": 0,
        "ts": datetime.now(UTC), "source": "admin_api",
        "event_type": "credential_revocation",
        "operation": {"name": f"credential {action}", "provider": preview.provider,
                      "target": preview.fingerprint, "outcome": outcome, "duration_ms": 0},
        "credential_ref": preview.fingerprint, "resource_refs": preview.reachable_resources,
        "payload": json.dumps({"action": action, "cold": preview.cold,
                               "events_last_30d": preview.events_last_30d,
                               "error_type": error_type}),
    })
    ingest_events(tenant_id, [event])
