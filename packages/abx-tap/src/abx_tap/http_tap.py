"""Byte-faithful Streamable HTTP tap for remote MCP servers (blueprint2 14.6).

The stdio pump proxies a child process; this proxies an HTTP origin. Same
promises: original bytes pass through untouched, parsing happens off the
forwarding path, and failure degrades recording rather than the agent.

Why this became tractable only with 2026-07-28: protocol sessions are gone, so
there is no session state to proxy, and the required `Mcp-Method` / `Mcp-Name`
headers let the tap route and attribute without parsing bodies.

Three constraints that shaped the implementation:

1. Servers reject requests whose headers and body DISAGREE. So the proxy
   forwards both faithfully and never repairs a mismatch - the disagreement is
   the signal, and rewriting it would hide an attempt to route one method while
   executing another.

2. The tap must never become a credential-laundering path. The Authorization
   header is forwarded verbatim and never stored: only a fingerprint, plus the
   unverified issuer and audience claims, are recorded.

3. SSE resumability was removed in 2026-07-28, so a broken response stream
   loses the in-flight request. That is recorded as an explicit incomplete
   operation rather than surfacing as a hang or a silent gap.

Stdlib only, like the rest of the tap.
"""

from __future__ import annotations

import contextlib
import json
import queue
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from abx_tap import mcp_spec
from abx_tap.pump import CLIENT_TO_SERVER, SERVER_TO_CLIENT, ObservedLine

READ_CHUNK = 65_536
UPSTREAM_TIMEOUT_SECONDS = 300


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect on the agent's behalf.

    urllib carries the request headers to the redirect target, INCLUDING
    Authorization, and including when the target is a different host. (The
    `requests` library strips it on a cross-host hop; urllib does not.) Since
    this proxy exists to forward OAuth bearer tokens to one operator-configured
    upstream, following a redirect hands that token to whatever host a Location
    header names - the upstream, anyone who can answer for it over plain http,
    or an internal address like the cloud metadata service. The agent sees 200
    and nothing looks wrong.

    Returning None leaves the 3xx unhandled, so it surfaces as an HTTPError and
    relays to the client verbatim, Location intact. That is the same treatment
    this module already gives a header/body disagreement: the proxy does not
    repair, it forwards and lets the client decide. Here the client is also the
    right decider - it holds the credential and knows which issuer it was
    keyed to, which the tap cannot see.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


#: Built once. Replaces the default redirect handler; keeps everything else.
_OPENER = urllib.request.build_opener(_NoRedirect)


def _forwardable(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in mcp_spec.HOP_BY_HOP
    }


def auth_refs(headers: dict[str, str]) -> list[str]:
    """Credential observations from an Authorization header.

    Fingerprint only. The issuer and audience claims are read WITHOUT
    signature verification - the tap holds no signing key - so they are named
    as claims. Recording them matters because 2026-07-28 requires clients to
    key credentials by issuer and validate RFC 9207 `iss`, and RFC 8707 binds a
    token to an audience: a token presented to an audience it was not issued
    for is exactly what audience binding exists to stop.
    """
    authorization = next(
        (
            value
            for key, value in headers.items()
            if key.lower() == mcp_spec.HEADER_AUTHORIZATION.lower()
        ),
        "",
    )
    if not authorization:
        return []
    fingerprint = mcp_spec.token_fingerprint(authorization)
    if fingerprint is None:
        return ["abx:mcp-auth-scheme:non-bearer"]
    refs = [f"abx:mcp-token:{fingerprint}"]
    raw = authorization.strip()[7:].strip()
    issuer = mcp_spec.issuer_of(raw)
    if issuer:
        refs.append(f"abx:mcp-token-issuer-claimed:{issuer[:200]}")
    for audience in mcp_spec.audience_of(raw)[:5]:
        refs.append(f"abx:mcp-token-audience-claimed:{audience[:200]}")
    return refs


class _Handler(BaseHTTPRequestHandler):
    upstream: str
    observe: queue.Queue[ObservedLine | None]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        """stdout stays clean; diagnostics belong on stderr."""

    def _observe(self, direction: str, raw: bytes) -> None:
        # Full queue drops the observation: recording degrades, the agent
        # never blocks.
        with contextlib.suppress(queue.Full):
            self.observe.put_nowait(ObservedLine(direction, raw))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {key: value for key, value in self.headers.items()}

        request_refs = auth_refs(headers)
        agreement = mcp_spec.header_matches_body(headers, body)
        if agreement is False:
            # Forwarded unrepaired: the server will reject it, and the attempt
            # is what we want on the record.
            request_refs.append("abx:mcp-header-body-mismatch:true")
        self._observe(CLIENT_TO_SERVER, body)
        if request_refs:
            self._observe(CLIENT_TO_SERVER, _synthetic(body, request_refs))

        request = urllib.request.Request(  # noqa: S310 - operator-configured destination, never a caller-supplied URL
            self.upstream, data=body, headers=_forwardable(headers), method="POST"
        )
        try:
            with _OPENER.open(request, timeout=UPSTREAM_TIMEOUT_SECONDS) as response:
                self._relay(response, body)
        except urllib.error.HTTPError as error:
            # An error response is a real response; forward it verbatim. A 3xx
            # arrives here too, because _NoRedirect declines to follow it.
            self._relay(error, body)
        except Exception:
            self._incomplete(body, "upstream_unreachable")

    def _relay(self, response: Any, request_body: bytes) -> None:
        raw_status = getattr(response, "status", None) or getattr(response, "code", None)
        status = int(raw_status) if isinstance(raw_status, int) else 502

        if 300 <= status < 400:
            # An upstream that redirects a credential-bearing call is worth
            # seeing. It is the shape of a token-harvesting redirect, and it is
            # also just how an operator finds out their upstream URL moved.
            location = response.headers.get("Location") or ""
            self._observe(SERVER_TO_CLIENT, _synthetic(request_body, [
                "abx:mcp-upstream-redirect-not-followed:true",
                f"abx:mcp-upstream-redirect-target:{location[:200]}",
            ]))

        self.send_response(status)
        for key, value in _forwardable(dict(response.headers.items())).items():
            self.send_header(key, value)
        self.end_headers()

        declared = response.headers.get("Content-Length")
        expected = int(declared) if declared and declared.isdigit() else None

        streamed = 0
        broke = False
        try:
            while chunk := response.read(READ_CHUNK):
                self.wfile.write(chunk)
                self.wfile.flush()
                streamed += len(chunk)
                self._observe(SERVER_TO_CLIENT, chunk)
        except Exception:
            broke = True

        # 2026-07-28 removed SSE resumability, so a broken stream loses the
        # in-flight request and the client must re-issue with a new id. Detect
        # it by comparing against the declared length rather than relying on an
        # exception: a short read can end the loop cleanly, and a silent
        # truncation looks identical to a completed call that returned less.
        if broke or (expected is not None and streamed < expected):
            self._observe(
                SERVER_TO_CLIENT,
                _synthetic(request_body, [
                    "abx:mcp-stream-incomplete:true",
                    f"abx:mcp-stream-bytes:{streamed}",
                    *([f"abx:mcp-stream-expected-bytes:{expected}"] if expected else []),
                ]),
            )

    def _incomplete(self, request_body: bytes, reason: str) -> None:
        self._observe(
            SERVER_TO_CLIENT,
            _synthetic(request_body, [f"abx:mcp-request-failed:{reason}"]),
        )
        self.send_response(502)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps({
                "jsonrpc": "2.0",
                "id": _request_id(request_body),
                "error": {"code": -32603, "message": "upstream MCP server unreachable"},
            }).encode()
        )


def _request_id(body: bytes) -> Any:
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    return parsed.get("id") if isinstance(parsed, dict) else None


def _synthetic(request_body: bytes, refs: list[str]) -> bytes:
    """A tap-authored observation line carrying derived refs.

    Shaped as a notification so the observer records it without disturbing
    request/response correlation. It is never sent to either party - the wire
    stays byte-faithful; this only enters the observation queue.
    """
    return json.dumps({
        "jsonrpc": "2.0",
        "method": "abx/observation",
        "params": {"refs": refs, "request_id": _request_id(request_body)},
    }).encode()


def serve(
    upstream: str,
    observe: queue.Queue[ObservedLine | None],
    port: int = 0,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Start the proxy. Returns (server, thread); caller shuts it down."""
    if not upstream.startswith(("http://", "https://")):
        raise ValueError("upstream MCP server must be an http(s) URL")

    handler = type("BoundHandler", (_Handler,), {"upstream": upstream, "observe": observe})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
