"""GET-only Google Workspace Admin SDK client for scanner workers.

Same shape as gcp_client and azure_client: no write method exists, non-GET
raises, and only the Admin SDK Directory and Reports paths the inventory needs
are reachable.

Two APIs, one host:
- Directory  - which OAuth tokens each user has issued to which application.
- Reports    - the token audit log, which is the ONLY source of usage freshness
               for Workspace tokens (blueprint 2.3 records that the Directory
               API exposes no last-used field).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlencode

from abx_scanner.readonly import CallCounter, ReadOnlyViolation

ADMIN_ROOT = "https://admin.googleapis.com"
ALLOWED_ROOTS = (ADMIN_ROOT,)
ALLOWED_PREFIXES = ("/admin/directory/v1/", "/admin/reports/v1/")
DIRECTORY_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.security.readonly"
REPORTS_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
# Both scopes are the readonly variants. Requesting a write scope would be a
# silent widening of the scan identity, so the constants are the guard.
SCOPES = (DIRECTORY_SCOPE, REPORTS_SCOPE)


@dataclass
class Response:
    status: int
    body: bytes


Opener = Callable[[str], Response]


class _AuthorizedResponse(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def content(self) -> bytes: ...


def _adc_opener() -> Opener:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    credentials, _project = google.auth.default(scopes=SCOPES)
    session = AuthorizedSession(credentials)  # type: ignore[no-untyped-call]

    def open_url(url: str) -> Response:
        response = cast(_AuthorizedResponse, session.get(url, timeout=30))
        return Response(status=response.status_code, body=response.content)

    return open_url


class WorkspaceClient:
    def __init__(
        self, opener: Opener | None = None, counter: CallCounter | None = None
    ) -> None:
        self.opener = opener or _adc_opener()
        self.counter = counter or CallCounter()

    def _request(
        self, method: str, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        if method != "GET":
            raise ReadOnlyViolation(
                f"scanner attempted {method} {path}; the scan path is read-only"
            )
        if not path.startswith(ALLOWED_PREFIXES):
            raise ValueError("unsupported Google Workspace scanner endpoint")
        query = f"?{urlencode(params)}" if params else ""
        self.counter.increment()
        response = self.opener(f"{ADMIN_ROOT}{path}{query}")
        if response.status != 200:
            message = response.body.decode("utf-8", "replace")[:500]
            raise WorkspaceError(response.status, message)
        value = json.loads(response.body) if response.body else {}
        if not isinstance(value, dict):
            raise WorkspaceError(response.status, "expected an object response")
        return value

    def get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        return self._request("GET", path, params)


class WorkspaceError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"google workspace api {status}: {message}")
        self.status = status
