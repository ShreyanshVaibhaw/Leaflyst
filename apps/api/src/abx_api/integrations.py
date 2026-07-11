"""Self-serve provider connection endpoints for phase 4."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Annotated, Any
from urllib.parse import urlencode

from abx_scanner.gh_auth import installation_details, now_epoch
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from abx_api.auth import require_admin
from abx_api.scan_queue import enqueue_github_scan
from abx_api.settings import settings
from abx_api.store import pg_pool

router = APIRouter(prefix="/v1/integrations")


class GitHubInstallLink(BaseModel):
    configured: bool
    install_url: str | None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_state(tenant_id: str, now: int | None = None) -> str:
    payload = json.dumps(
        {"tenant_id": tenant_id, "exp": (now or int(time.time())) + 15 * 60},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    encoded = _b64(payload)
    signature = hmac.new(
        settings.github_state_secret.encode(), encoded.encode(), hashlib.sha256
    ).digest()
    return f"{encoded}.{_b64(signature)}"


def parse_state(state: str, now: int | None = None) -> str:
    try:
        encoded, supplied = state.split(".", 1)
        expected = hmac.new(
            settings.github_state_secret.encode(), encoded.encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_unb64(supplied), expected):
            raise ValueError("signature")
        payload = json.loads(_unb64(encoded))
        if int(payload["exp"]) < (now or int(time.time())):
            raise ValueError("expired")
        tenant_id = str(payload["tenant_id"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid or expired integration state") from exc
    return tenant_id


@router.get(
    "/github/install-url",
    response_model=GitHubInstallLink,
    dependencies=[Depends(require_admin)],
)
def github_install_url(tenant_id: str) -> GitHubInstallLink:
    if not settings.github_app_slug:
        return GitHubInstallLink(configured=False, install_url=None)
    query = urlencode({"state": make_state(tenant_id)})
    return GitHubInstallLink(
        configured=True,
        install_url=(
            f"https://github.com/apps/{settings.github_app_slug}/installations/new?{query}"
        ),
    )


@router.get("/github/setup", include_in_schema=False)
def github_setup(
    installation_id: str,
    state: str,
    setup_action: Annotated[str | None, "GitHub setup action"] = None,
) -> RedirectResponse:
    tenant_id = parse_state(state)
    if not settings.github_app_id or not settings.github_private_key:
        raise HTTPException(status_code=503, detail="GitHub App credentials are not configured")

    details = installation_details(
        settings.github_app_id,
        settings.github_private_key,
        installation_id,
        now_epoch(),
    )
    account = details.get("account")
    org = str(account.get("login", "")) if isinstance(account, dict) else ""
    if details.get("target_type") != "Organization" or not org:
        raise HTTPException(
            status_code=400, detail="GitHub App must be installed on an organization"
        )

    metadata: dict[str, Any] = {
        "repository_selection": details.get("repository_selection"),
        "setup_action": setup_action,
    }
    with pg_pool().connection() as conn:
        conn.execute(
            "INSERT INTO integration_connections "
            "(tenant_id, provider, external_id, account_login, status, metadata) "
            "VALUES (%s, 'github', %s, %s, 'connected', %s) "
            "ON CONFLICT (tenant_id, provider, external_id) DO UPDATE SET "
            "account_login = EXCLUDED.account_login, status = 'connected', "
            "metadata = EXCLUDED.metadata, updated_at = now()",
            (tenant_id, installation_id, org, Jsonb(metadata)),
        )
    enqueue_github_scan(tenant_id, installation_id, org)
    return RedirectResponse(
        f"{settings.web_url.rstrip('/')}/integrations?github=connected&org={org}", status_code=303
    )
