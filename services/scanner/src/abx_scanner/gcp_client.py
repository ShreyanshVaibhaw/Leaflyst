"""GET-only Google Cloud REST client for scanner workers.

Application Default Credentials are resolved inside the worker process. The
client exposes no write method, rejects non-GET attempts, and accepts only the
IAM and Cloud Asset API roots used by the inventory path.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlencode

import google.auth
from google.auth.transport.requests import AuthorizedSession

from abx_scanner.readonly import CallCounter, ReadOnlyViolation

IAM_ROOT = "https://iam.googleapis.com"
ASSET_ROOT = "https://cloudasset.googleapis.com"
ALLOWED_ROOTS = (IAM_ROOT, ASSET_ROOT)
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


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
    credentials, _project = google.auth.default(scopes=(CLOUD_PLATFORM_SCOPE,))
    session = AuthorizedSession(credentials)  # type: ignore[no-untyped-call]

    def open_url(url: str) -> Response:
        response = cast(_AuthorizedResponse, session.get(url, timeout=30))
        return Response(status=response.status_code, body=response.content)

    return open_url


class GcpClient:
    def __init__(
        self,
        opener: Opener | None = None,
        counter: CallCounter | None = None,
    ) -> None:
        self.opener = opener or _adc_opener()
        self.counter = counter or CallCounter()

    def _request(
        self, method: str, root: str, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        if method != "GET":
            raise ReadOnlyViolation(
                f"scanner attempted {method} {path}; the scan path is read-only"
            )
        if root not in ALLOWED_ROOTS or not path.startswith("/v1/"):
            raise ValueError("unsupported Google Cloud scanner endpoint")
        query = f"?{urlencode(params)}" if params else ""
        self.counter.increment()
        response = self.opener(f"{root}{path}{query}")
        if response.status != 200:
            message = response.body.decode("utf-8", "replace")[:500]
            raise GcpError(response.status, message)
        value = json.loads(response.body) if response.body else {}
        if not isinstance(value, dict):
            raise GcpError(response.status, "expected an object response")
        return value

    def iam_get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        return self._request("GET", IAM_ROOT, path, params)

    def asset_get(
        self, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return self._request("GET", ASSET_ROOT, path, params)


class GcpError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"google cloud api {status}: {message}")
        self.status = status
