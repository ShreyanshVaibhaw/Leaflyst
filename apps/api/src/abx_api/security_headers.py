"""Response headers and banner suppression for the API (SEC-B06).

This service answers with JSON describing one tenant's credentials, agent
sessions, and recorded payloads. None of it should ever be cached by an
intermediary, framed, sniffed into another content type, or carried as a
referrer to somewhere else, and none of it needs to load a script, a font, or
an image. The header set below says exactly that, which is why the content
policy is `default-src 'none'` rather than a copy of a web application's.

HSTS is emitted only where HTTPS is actually required. Sending it over plain
HTTP is at best ignored and at worst pins a browser to a scheme the deployment
cannot serve, which is a self-inflicted outage rather than a control.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from abx_api.settings import settings

BASE_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-site"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    # Tenant data must not sit in a proxy or browser cache after the session
    # that fetched it has gone.
    (b"cache-control", b"no-store"),
)

HSTS = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")


def interactive_docs_enabled(environment: str) -> bool:
    """Whether to mount /docs, /redoc, and /openapi.json.

    They publish the whole route inventory, every schema, and a form that issues
    real authenticated requests. That is the right trade while developing and
    the wrong one on a public host, where it hands an attacker the map for free.
    The generated apps/api/openapi.json stays the contract of record either way.
    """
    return environment != "production"


class SecurityHeaders:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.headers = BASE_HEADERS + ((HSTS,) if settings.require_https else ())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                existing = {name.lower() for name, _ in message.get("headers", [])}
                message["headers"] = [
                    header
                    for header in message.get("headers", [])
                    # uvicorn's banner names the server and its version, which is
                    # a free hint about which advisories to try.
                    if header[0].lower() != b"server"
                ] + [
                    (name, value) for name, value in self.headers if name not in existing
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)
