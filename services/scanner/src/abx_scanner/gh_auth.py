"""GitHub App authentication: App JWT -> installation access token.

Enumerating org fine-grained PATs is callable ONLY by a GitHub App
installation token (hard platform constraint), so App auth is required for a
real scan. Dev/tests use a PAT directly and skip this module.
"""

from __future__ import annotations

import json
import time
import urllib.request

import jwt

from abx_scanner.gh_client import API_ROOT, API_VERSION


def app_jwt(app_id: str, private_key_pem: str, now: int) -> str:
    """Short-lived RS256 JWT identifying the App (max 10 min per GitHub)."""
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def installation_token(
    app_id: str, private_key_pem: str, installation_id: str, now: int
) -> str:
    """Exchange the App JWT for a short-lived installation access token."""
    token = app_jwt(app_id, private_key_pem, now)
    req = urllib.request.Request(  # noqa: S310 - github api over https
        f"{API_ROOT}/app/installations/{installation_id}/access_tokens",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "agentblackbox-scanner",
        },
        data=b"",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return str(json.loads(resp.read())["token"])


def installation_details(
    app_id: str, private_key_pem: str, installation_id: str, now: int
) -> dict[str, object]:
    """Validate an installation against this App and return its public metadata.

    GitHub's setup URL parameter is attacker-controlled. An App JWT can only
    retrieve installations belonging to that App, making this lookup the
    trust boundary before a tenant connection is persisted.
    """
    token = app_jwt(app_id, private_key_pem, now)
    req = urllib.request.Request(  # noqa: S310 - github api over https
        f"{API_ROOT}/app/installations/{installation_id}",
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "agentblackbox-scanner",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        value = json.loads(resp.read())
    if not isinstance(value, dict):
        raise ValueError("GitHub returned an invalid installation response")
    return value


def now_epoch() -> int:
    """Wall-clock seconds. Isolated so callers/tests can inject time."""
    return int(time.time())
