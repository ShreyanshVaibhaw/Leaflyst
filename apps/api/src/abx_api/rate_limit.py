"""Layered request limits at the public edge (plansecurity SP-2).

Three limits, because one is never enough:

- per caller, which stops a single token or address from monopolising the API;
- per caller on costly routes, because thirty evidence-pack builds cost more
  than six hundred dashboard reads and a single counter cannot say so; and
- global, because the first two are per identity and an attacker can bring more
  identities than the database can serve.

The caller identity is a token fingerprint when a credential is presented and
the client address otherwise. Fingerprints are salted SHA-256 truncated to 16
hex characters: enough to separate callers, never enough to recover the token
from whatever can read Redis.

Failure mode. If Redis is unreachable the limiter allows the request. That is
deliberate and it follows the recording-plane invariant: the tap and SDK degrade
recording rather than block the agent, so a limiter outage must not become an
outage of the thing being recorded. It is also why the limiter is not the only
control - the edge proxy carries its own limits, and the body-size bounds in
front of every parser do not depend on Redis at all.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from abx_api.scan_queue import redis_client
from abx_api.settings import settings

#: Substrings that mark a route as expensive. Matched against the raw path
#: because this runs before routing, so no path template is available yet.
COSTLY_MARKERS = (
    "/v1/compliance/",
    "/v1/evidence/",
    "/v1/reports/",
    "/v1/demo/",
    "/v1/chain/verify",
    "/blast-radius",
    "/v1/scans/local",
)

EXEMPT_PATHS = frozenset({"/healthz", "/readyz"})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    scope: str
    retry_after: int


def client_address(scope: Scope) -> str:
    """The client address, trusting forwarded headers only as far as configured.

    With zero trusted hops the peer address wins outright. With N hops, the
    (N+1)-th entry from the right of X-Forwarded-For is the first value the
    trusted proxies did not themselves append, and everything to its left was
    written by someone we have no reason to believe.
    """
    peer = scope.get("client")
    peer_host = str(peer[0]) if peer else "unknown"
    hops = settings.trusted_proxy_hops
    if hops <= 0:
        return peer_host
    headers = dict(scope.get("headers", []))
    raw = headers.get(b"x-forwarded-for", b"").decode("latin-1")
    chain: list[str] = [str(part).strip() for part in raw.split(",") if part.strip()]
    if len(chain) < hops:
        # Fewer hops than declared means this did not arrive through the
        # configured path. Fall back to the peer rather than guess.
        return peer_host
    return chain[-hops]


def caller_identity(scope: Scope) -> str:
    """Who to charge this request to: the credential if there is one, else the address."""
    headers = dict(scope.get("headers", []))
    for header in (b"authorization", b"x-abx-admin-key"):
        raw = headers.get(header, b"")
        if raw:
            digest = hashlib.sha256(b"abx-rate-limit:" + raw).hexdigest()[:16]
            return f"tok:{digest}"
    return f"ip:{client_address(scope)}"


def _over_limit(key: str, limit: int, window: int) -> bool:
    """Fixed-window counter. Returns True when this request exceeds the limit."""
    client = redis_client()
    count = int(client.incr(key))
    if count == 1:
        client.expire(key, window)
    return count > limit


def check(scope: Scope, bucket: int) -> Decision:
    """Evaluate every applicable limit for one request."""
    window = settings.rate_limit_window_seconds
    path = str(scope.get("path", ""))
    identity = caller_identity(scope)
    checks = [("global", f"abx:rl:g:{bucket}", settings.rate_limit_global_requests)]
    if any(marker in path for marker in COSTLY_MARKERS):
        checks.append(
            ("costly", f"abx:rl:c:{identity}:{bucket}", settings.rate_limit_costly_requests)
        )
    checks.append(("caller", f"abx:rl:i:{identity}:{bucket}", settings.rate_limit_requests))
    for name, key, limit in checks:
        if limit > 0 and _over_limit(key, limit, window):
            return Decision(False, name, window)
    return Decision(True, "", 0)


class RateLimit:
    """ASGI middleware applying the limits above before anything is parsed."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or not settings.rate_limit_enabled
            or str(scope.get("path", "")) in EXEMPT_PATHS
        ):
            await self.app(scope, receive, send)
            return
        try:
            bucket = int(time.time()) // max(1, settings.rate_limit_window_seconds)
            decision = check(scope, bucket)
        except Exception:  # noqa: BLE001 - see the failure-mode note in the module docstring
            await self.app(scope, receive, send)
            return
        if decision.allowed:
            await self.app(scope, receive, send)
            return
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"retry-after", str(decision.retry_after).encode()),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"detail":"rate limit exceeded"}',
            }
        )
