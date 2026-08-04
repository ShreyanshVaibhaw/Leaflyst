"""Reject requests that cannot be answered before anything tries (SP-4).

A NUL byte in a query string is not a value the application can do anything
useful with. Postgres refuses it outright - a text parameter containing 0x00 is
a hard error, not an empty result - so every string parameter that reaches a
query turns a NUL into a 500. That was reproducible on four parameters across
two routers, and it would have been true of the next such parameter as well,
because nothing about it is per-route.

Fixing it per parameter would mean remembering, on every future filter, that a
character nobody types has to be excluded. Rejecting it once at the edge means
the rule holds for parameters that do not exist yet.

500 versus 400 matters here beyond tidiness. A 500 is indistinguishable from a
genuine fault, so it pollutes the error rate an operator would page on, and it
tells a caller that their input travelled far enough to break something rather
than being refused at the door.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

#: Percent-encoded and raw forms. A client may send either; Starlette decodes
#: the first into the second before a handler ever sees it.
_FORBIDDEN = (b"%00", b"\x00")


def has_null_byte(raw: bytes) -> bool:
    return any(marker in raw.lower() for marker in _FORBIDDEN)


class RejectNullBytes:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        query = scope.get("query_string", b"") or b""
        path = str(scope.get("raw_path") or scope.get("path", "")).encode("latin-1", "replace")
        if has_null_byte(query) or has_null_byte(path):
            await send(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"detail":"request contains a null byte"}',
                }
            )
            return
        await self.app(scope, receive, send)
