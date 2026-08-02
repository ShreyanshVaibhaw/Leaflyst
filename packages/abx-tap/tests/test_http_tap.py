"""Streamable HTTP tap: byte-faithful proxying of a remote MCP server.

Driven against a real HTTP origin in-process, not a mocked transport, because
the properties under test are transport properties: bytes crossing unchanged,
headers surviving intact, and a broken stream being recorded rather than
silently truncated.

The security property that matters most: the tap forwards OAuth bearer tokens
and must never become a credential-laundering path. Only a fingerprint and the
unverified issuer/audience claims are ever recorded.
"""

from __future__ import annotations

import contextlib
import json
import queue
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from abx_tap import mcp_spec
from abx_tap.http_tap import auth_refs, serve
from abx_tap.observer import Observer

# header.{"iss":"https://auth.example.com","aud":"https://mcp.example.com"}.sig
JWT = (
    "eyJhbGciOiJSUzI1NiJ9."
    "eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL21jcC5leGFtcGxlLmNvbSJ9"
    ".c2ln"
)


class _Origin(BaseHTTPRequestHandler):
    """A minimal modern MCP server that records what it received."""

    received: list[dict] = []
    mode = "ok"

    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _Origin.received.append({
            "body": body,
            "headers": {k: v for k, v in self.headers.items()},
        })
        if _Origin.mode == "truncate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "9999")
            self.end_headers()
            self.wfile.write(b'{"partial"')
            self.wfile.flush()
            self.close_connection = True
            return
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "result": {"resultType": "complete", "tools": []},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def origin():
    _Origin.received = []
    _Origin.mode = "ok"
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


@pytest.fixture
def tap(origin):
    observe: queue.Queue = queue.Queue(maxsize=1000)
    upstream = f"http://127.0.0.1:{origin.server_address[1]}/mcp"
    server, _thread = serve(upstream, observe, port=0)
    yield f"http://127.0.0.1:{server.server_address[1]}/mcp", observe
    server.shutdown()


def post(url: str, body: dict, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    raw = json.dumps(body).encode()
    request = urllib.request.Request(
        url, data=raw, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def drain(observe: queue.Queue) -> list[bytes]:
    lines = []
    while not observe.empty():
        item = observe.get_nowait()
        if item is not None:
            lines.append(item.raw)
    return lines


def refs_from(observe: queue.Queue) -> list[str]:
    """Everything the observer derives from what the tap saw."""
    ob = Observer(agent_id="http-agent", server_name="remote")
    out: list[str] = []
    for raw in drain(observe):
        for event in ob.observe(type("L", (), {"direction": "c2s", "raw": raw})()):
            out.extend(event["resource_refs"])
    return out


# -- byte fidelity ------------------------------------------------------------

def test_request_body_and_headers_reach_the_origin_unchanged(tap) -> None:
    """Servers reject requests whose headers and body disagree, so anything
    the proxy rewrites breaks the session it is observing."""
    url, _observe = tap
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    status, _ = post(url, body, {
        mcp_spec.HEADER_MCP_METHOD: "tools/list",
        mcp_spec.HEADER_MCP_NAME: "list-tools",
        mcp_spec.HEADER_PROTOCOL_VERSION: "2026-07-28",
    })
    assert status == 200
    seen = _Origin.received[0]
    assert json.loads(seen["body"]) == body
    # HTTP field names are case-insensitive (RFC 9110) and urllib normalizes
    # their case, so presence and value are what must survive, not casing.
    received = {key.lower(): value for key, value in seen["headers"].items()}
    assert received[mcp_spec.HEADER_MCP_METHOD.lower()] == "tools/list"
    assert received[mcp_spec.HEADER_MCP_NAME.lower()] == "list-tools"
    assert received[mcp_spec.HEADER_PROTOCOL_VERSION.lower()] == "2026-07-28"


def test_response_body_reaches_the_client_unchanged(tap) -> None:
    url, _observe = tap
    status, payload = post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert status == 200
    assert json.loads(payload)["result"]["resultType"] == "complete"


def test_hop_by_hop_headers_are_not_forwarded(tap) -> None:
    url, _observe = tap
    post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
         {"Connection": "keep-alive", "Te": "trailers"})
    forwarded = {k.lower() for k in _Origin.received[0]["headers"]}
    assert "te" not in forwarded


# -- OAuth ---------------------------------------------------------------------

def test_bearer_token_is_forwarded_but_never_recorded(tap) -> None:
    """The tap must not become a credential-laundering path."""
    url, observe = tap
    post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
         {"Authorization": f"Bearer {JWT}"})

    # Forwarded verbatim, or the upstream session breaks.
    forwarded = {k.lower(): v for k, v in _Origin.received[0]["headers"].items()}
    assert forwarded["authorization"] == f"Bearer {JWT}"

    observed = b" ".join(drain(observe)).decode()
    assert JWT not in observed
    assert "Bearer" not in observed


def test_token_is_recorded_as_a_fingerprint_with_unverified_claims() -> None:
    refs = auth_refs({"Authorization": f"Bearer {JWT}"})
    assert any(ref.startswith("abx:mcp-token:mcptoken:") for ref in refs)
    # RFC 9207 issuer and RFC 8707 audience, read without signature
    # verification, so both are named as claims.
    assert "abx:mcp-token-issuer-claimed:https://auth.example.com" in refs
    assert "abx:mcp-token-audience-claimed:https://mcp.example.com" in refs
    assert not any(JWT in ref for ref in refs)


def test_the_same_token_fingerprints_identically_and_a_different_one_does_not() -> None:
    first = mcp_spec.token_fingerprint(f"Bearer {JWT}")
    assert first == mcp_spec.token_fingerprint(f"Bearer {JWT}")
    assert first != mcp_spec.token_fingerprint("Bearer other-token")
    assert mcp_spec.token_fingerprint("Basic abc") is None


def test_non_bearer_authorization_is_noted_without_its_value() -> None:
    refs = auth_refs({"Authorization": "Basic c2VjcmV0OnZhbHVl"})
    assert refs == ["abx:mcp-auth-scheme:non-bearer"]


# -- header/body agreement -----------------------------------------------------

def test_header_body_mismatch_is_recorded_and_not_repaired(tap) -> None:
    """Rewriting the header to match would hide an attempt to route one method
    while executing another - the exact mismatch class the spec closed."""
    url, observe = tap
    post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
         {mcp_spec.HEADER_MCP_METHOD: "tools/list"})

    # Forwarded unrepaired; the origin decides.
    routed = {k.lower(): v for k, v in _Origin.received[0]["headers"].items()}
    assert routed[mcp_spec.HEADER_MCP_METHOD.lower()] == "tools/list"
    assert json.loads(_Origin.received[0]["body"])["method"] == "tools/call"
    assert "abx:mcp-header-body-mismatch:true" in refs_from(observe)


def test_agreeing_header_and_body_raise_no_flag(tap) -> None:
    url, observe = tap
    post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
         {mcp_spec.HEADER_MCP_METHOD: "tools/list"})
    assert "abx:mcp-header-body-mismatch:true" not in refs_from(observe)


def test_mismatch_check_does_not_apply_without_the_header() -> None:
    assert mcp_spec.header_matches_body({}, b'{"method":"tools/list"}') is None
    assert mcp_spec.header_matches_body({"Mcp-Method": "x"}, b"not json") is None


# -- incompleteness ------------------------------------------------------------

def test_broken_stream_is_recorded_as_incomplete(tap) -> None:
    """SSE resumability was removed in 2026-07-28, so a broken stream loses the
    in-flight request. A silent truncation would look like a completed call
    that simply returned less."""
    url, observe = tap
    _Origin.mode = "truncate"
    with contextlib.suppress(Exception):
        post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert "abx:mcp-stream-incomplete:true" in refs_from(observe)


def test_unreachable_upstream_answers_the_agent_and_records_the_failure() -> None:
    """Failure mode is always 'agent keeps working, recording degrades'."""
    observe: queue.Queue = queue.Queue(maxsize=100)
    server, _thread = serve("http://127.0.0.1:1/unreachable", observe, port=0)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
        status, payload = post(url, {"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
    finally:
        server.shutdown()

    # The agent gets a well-formed JSON-RPC error rather than a hang.
    assert status == 502
    answer = json.loads(payload)
    assert answer["id"] == 7
    assert answer["error"]["code"] == -32603
    assert "abx:mcp-request-failed:upstream_unreachable" in refs_from(observe)


def test_upstream_must_be_an_http_url() -> None:
    with pytest.raises(ValueError):
        serve("ftp://example.com", queue.Queue(), port=0)
