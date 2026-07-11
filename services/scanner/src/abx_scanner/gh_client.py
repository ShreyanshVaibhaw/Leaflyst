"""Read-only GitHub REST client (stdlib urllib).

Read-only by construction: the client exposes GET only; `_request` raises on
any other method (mirrors the AWS read-only guard, engineering invariant 3).
Revocation (Phase 7) uses a separate client with write scopes.

The HTTP layer is injectable (`opener`) so tests drive canned responses
without a live server or network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from abx_scanner.readonly import CallCounter, ReadOnlyViolation

API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


# An opener maps a urllib Request to a Response (mockable in tests).
Opener = Callable[[urllib.request.Request], Response]


def _urllib_opener(req: urllib.request.Request) -> Response:
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return Response(resp.status, dict(resp.headers), resp.read())
    except urllib.error.HTTPError as e:
        return Response(e.code, dict(e.headers or {}), e.read())


class GitHubClient:
    def __init__(
        self,
        token: str,
        counter: CallCounter | None = None,
        opener: Opener | None = None,
        api_root: str = API_ROOT,
    ) -> None:
        self.token = token
        self.counter = counter or CallCounter()
        self.opener = opener or _urllib_opener
        self.api_root = api_root

    def _request(self, method: str, path: str) -> Response:
        if method != "GET":
            raise ReadOnlyViolation(
                f"scanner attempted {method} {path}; the scan path is read-only"
            )
        url = path if path.startswith("http") else self.api_root + path
        req = urllib.request.Request(  # noqa: S310 - github api over https
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "agentblackbox-scanner",
            },
        )
        self.counter.increment()
        return self.opener(req)

    def get(self, path: str) -> Any:
        resp = self._request("GET", path)
        if resp.status == 200:
            return json.loads(resp.body) if resp.body else None
        if resp.status == 404:
            return None
        raise GitHubError(resp.status, resp.body.decode("utf-8", "replace")[:500])

    def paginate(self, path: str, item_key: str | None = None) -> list[Any]:
        """Follow Link rel="next"; flatten pages. item_key extracts a list
        field from an object response (e.g. 'installations')."""
        items: list[Any] = []
        next_path: str | None = path
        while next_path:
            resp = self._request("GET", next_path)
            if resp.status != 200:
                if resp.status == 404:
                    break
                raise GitHubError(resp.status, resp.body.decode("utf-8", "replace")[:500])
            data = json.loads(resp.body) if resp.body else []
            page = data.get(item_key, []) if item_key and isinstance(data, dict) else data
            items.extend(page)
            next_path = _next_link(resp.headers.get("Link", ""))
        return items


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"github api {status}: {message}")
        self.status = status


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        segs = part.split(";")
        if len(segs) < 2:
            continue
        url = segs[0].strip().lstrip("<").rstrip(">")
        if 'rel="next"' in part:
            return url
    return None
