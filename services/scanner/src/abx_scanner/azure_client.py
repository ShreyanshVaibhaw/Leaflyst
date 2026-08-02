"""GET-only Microsoft Graph and ARM client for scanner workers.

Same shape as gcp_client: credentials are resolved inside the worker process,
the client exposes no write method, rejects any non-GET attempt, and accepts
only the API roots the inventory path needs.

The read-only guarantee is enforced here rather than relied upon from IAM
alone. A scan role misconfigured with write permission still cannot mutate,
because there is no code path that issues a mutating verb (blueprint 6).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlencode

from abx_scanner.readonly import CallCounter, ReadOnlyViolation

GRAPH_ROOT = "https://graph.microsoft.com"
ARM_ROOT = "https://management.azure.com"
ALLOWED_ROOTS = (GRAPH_ROOT, ARM_ROOT)
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"


@dataclass
class Response:
    status: int
    body: bytes


Opener = Callable[[str], Response]


class _TokenCredential(Protocol):
    def get_token(self, *scopes: str) -> Any: ...


def _default_opener() -> Opener:
    """Azure default credential chain, resolved lazily.

    Imported inside the function so unit tests can inject an opener without
    the azure SDK being installed.
    """
    import requests
    from azure.identity import DefaultAzureCredential

    credential = cast(_TokenCredential, DefaultAzureCredential())

    def open_url(url: str) -> Response:
        scope = ARM_SCOPE if url.startswith(ARM_ROOT) else GRAPH_SCOPE
        token = credential.get_token(scope).token
        response = requests.get(
            url, headers={"Authorization": f"Bearer {token}"}, timeout=30
        )
        return Response(status=response.status_code, body=response.content)

    return open_url


class AzureClient:
    def __init__(
        self,
        opener: Opener | None = None,
        counter: CallCounter | None = None,
    ) -> None:
        self.opener = opener or _default_opener()
        self.counter = counter or CallCounter()

    def _request(
        self, method: str, root: str, path: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        if method != "GET":
            raise ReadOnlyViolation(
                f"scanner attempted {method} {path}; the scan path is read-only"
            )
        if root not in ALLOWED_ROOTS:
            raise ValueError("unsupported Azure scanner endpoint")
        query = f"?{urlencode(params)}" if params else ""
        self.counter.increment()
        response = self.opener(f"{root}{path}{query}")
        if response.status != 200:
            message = response.body.decode("utf-8", "replace")[:500]
            raise AzureError(response.status, message)
        value = json.loads(response.body) if response.body else {}
        if not isinstance(value, dict):
            raise AzureError(response.status, "expected an object response")
        return value

    def graph_get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        if not path.startswith("/v1.0/"):
            raise ValueError("unsupported Microsoft Graph scanner endpoint")
        return self._request("GET", GRAPH_ROOT, path, params)

    def arm_get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        if not path.startswith("/subscriptions/"):
            raise ValueError("unsupported Azure Resource Manager scanner endpoint")
        return self._request("GET", ARM_ROOT, path, params)


class AzureError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"azure api {status}: {message}")
        self.status = status
