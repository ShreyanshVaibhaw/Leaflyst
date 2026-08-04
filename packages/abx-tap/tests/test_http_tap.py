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
from types import SimpleNamespace
from urllib.request import build_opener

import pytest
from abx_tap import mcp_spec
from abx_tap.http_tap import _NoRedirect, auth_refs, serve
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

    def do_POST(self) -> None:
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


# -- the bearer token does not travel to a redirect target (SP-6b) -------------

def _drain_request_body(handler: BaseHTTPRequestHandler) -> None:
    """Consume the request body before replying.

    A handler that answers and closes without reading leaves the client writing
    into a socket nobody is draining, which surfaces as a connection reset
    rather than as the response - and the tap reports that as an unreachable
    upstream. Real servers read their input; these must too, or the test is
    racing the socket instead of testing the proxy.
    """
    length = int(handler.headers.get("Content-Length") or 0)
    if length:
        handler.rfile.read(length)


class _Harvester(BaseHTTPRequestHandler):
    """Stands in for wherever a Location header points."""

    seen: list[str] = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def _answer(self) -> None:
        _drain_request_body(self)
        _Harvester.seen.append(self.headers.get("Authorization") or "<none>")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = _answer
    do_POST = _answer


@pytest.fixture
def redirecting_upstream():
    """An upstream whose only answer is 'go ask that other host instead'."""
    _Harvester.seen = []
    harvester = ThreadingHTTPServer(("127.0.0.1", 0), _Harvester)
    threading.Thread(target=harvester.serve_forever, daemon=True).start()
    elsewhere = f"http://127.0.0.1:{harvester.server_address[1]}/collect"

    class _Redirector(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: object) -> None:
            pass

        def do_POST(self) -> None:
            _drain_request_body(self)
            self.send_response(302)
            self.send_header("Location", elsewhere)
            self.send_header("Content-Length", "0")
            self.end_headers()

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    upstream_url = f"http://127.0.0.1:{upstream.server_address[1]}/mcp"
    observe: queue.Queue = queue.Queue(maxsize=1000)
    tap_server, _thread = serve(upstream_url, observe, port=0)
    yield SimpleNamespace(
        tap=f"http://127.0.0.1:{tap_server.server_address[1]}/mcp",
        observe=observe,
        elsewhere=elsewhere,
        upstream=upstream_url,
    )
    tap_server.shutdown()
    upstream.shutdown()
    harvester.shutdown()


def post_without_following(url: str, body: dict, headers: dict[str, str]) -> int:
    """POST with a client that does NOT follow redirects.

    The helper above uses a stock opener, which follows a 302 and carries
    Authorization with it. That would put the token on the harvester by the test
    client's own doing and prove nothing about the tap.
    """
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with build_opener(_NoRedirect).open(request, timeout=10) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


def test_a_redirect_does_not_carry_the_bearer_token_to_another_host(
    redirecting_upstream,
) -> None:
    """The tap must not fetch a Location target with the agent's credential.

    urllib re-sends request headers to a redirect target, Authorization
    included, and across hosts - where `requests` would strip it. A proxy that
    follows redirects therefore hands the token to whatever host the upstream
    names: an attacker's, or an internal address like the metadata service. The
    agent sees 200 and nothing looks wrong.

    The 3xx is relayed rather than converted to an error. Without the tap in the
    path the client would receive that same 302 from the upstream directly, so
    relaying keeps the observable behaviour identical - which is the whole point
    of a byte-faithful proxy. What must not happen is the tap ADDING a hop the
    operator never configured and cannot see.
    """
    secret = "Bearer ghp_" + "z" * 36
    status = post_without_following(
        redirecting_upstream.tap,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
        {"Authorization": secret},
    )

    assert _Harvester.seen == [], "the tap carried the bearer token to the redirect target"
    assert status == 302, f"the redirect was not passed through (got {status})"


def test_the_refused_redirect_is_visible_on_the_record(redirecting_upstream) -> None:
    """An upstream redirecting a credential-bearing call is worth seeing."""
    post_without_following(
        redirecting_upstream.tap,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},
        {"Authorization": "Bearer ghp_" + "z" * 36},
    )
    refs = refs_from(redirecting_upstream.observe)
    assert "abx:mcp-upstream-redirect-not-followed:true" in refs
    assert any(redirecting_upstream.elsewhere in ref for ref in refs), refs


def test_the_leak_is_real_without_the_handler(redirecting_upstream) -> None:
    """The negative control the SP-6 gate's rule asks for.

    "The harvester saw nothing" would also be true if the request never left the
    building. So this drives the SAME redirect through a stock urllib opener -
    exactly what the tap used before this fix - and shows the token arriving at
    the other host. If this test ever stops leaking, the test above has stopped
    measuring anything.
    """
    secret = "Bearer ghp_" + "y" * 36
    request = urllib.request.Request(
        redirecting_upstream.upstream, data=b"{}", method="POST",
        headers={"Content-Type": "application/json", "Authorization": secret},
    )
    with contextlib.suppress(urllib.error.HTTPError, urllib.error.URLError):
        urllib.request.urlopen(request, timeout=10).read()

    assert _Harvester.seen == [secret], (
        "a default opener no longer forwards Authorization across a redirect, "
        "so the containment test above proves nothing"
    )
