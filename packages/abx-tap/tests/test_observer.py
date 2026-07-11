import json

from abx_schemas import IngestEvent
from abx_tap.observer import Observer, tools_hash
from abx_tap.pump import CLIENT_TO_SERVER, SERVER_TO_CLIENT, ObservedLine


def c2s(obj: dict) -> ObservedLine:
    return ObservedLine(CLIENT_TO_SERVER, (json.dumps(obj) + "\n").encode())


def s2c(obj: dict) -> ObservedLine:
    return ObservedLine(SERVER_TO_CLIENT, (json.dumps(obj) + "\n").encode())


def make_observer() -> Observer:
    return Observer(agent_id="test-agent", server_name="fake")


def test_request_response_correlation_and_schema() -> None:
    ob = make_observer()
    req = ob.observe(c2s({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "echo", "arguments": {"path": "/tmp/x"}}}))
    resp = ob.observe(s2c({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}))
    assert len(req) == 1 and len(resp) == 1
    assert req[0]["event_type"] == "mcp_request"
    assert req[0]["operation"]["outcome"] == "unknown"
    assert req[0]["operation"]["target"] == "echo"
    assert "/tmp/x" in req[0]["resource_refs"]
    assert resp[0]["event_type"] == "mcp_response"
    assert resp[0]["operation"]["outcome"] == "success"
    assert resp[0]["operation"]["duration_ms"] is not None
    # Every produced dict must validate against the shared contract.
    for e in req + resp:
        IngestEvent.model_validate(e)


def test_out_of_order_responses() -> None:
    ob = make_observer()
    ob.observe(c2s({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "a"}}))
    ob.observe(c2s({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "b"}}))
    r2 = ob.observe(s2c({"jsonrpc": "2.0", "id": 2, "result": {}}))
    r1 = ob.observe(s2c({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}))
    assert r2[0]["operation"]["target"] == "b"
    assert r1[0]["operation"]["target"] == "a"
    assert r1[0]["operation"]["outcome"] == "error"


def test_same_id_both_directions_no_collision() -> None:
    ob = make_observer()
    ob.observe(c2s({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}}))
    # Server-initiated request reusing id 1 (sampling goes server -> client).
    ob.observe(s2c({"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {}}))
    client_reply = ob.observe(c2s({"jsonrpc": "2.0", "id": 1, "result": {"role": "assistant"}}))
    server_reply = ob.observe(s2c({"jsonrpc": "2.0", "id": 1, "result": {}}))
    assert client_reply[0]["operation"]["name"] == "sampling/createMessage"
    assert server_reply[0]["operation"]["target"] == "t"


def test_notification_emits_single_event() -> None:
    ob = make_observer()
    events = ob.observe(c2s({"jsonrpc": "2.0", "method": "notifications/cancelled"}))
    assert len(events) == 1
    assert events[0]["operation"]["outcome"] == "success"


def test_initialize_captures_protocol_version() -> None:
    ob = make_observer()
    ob.observe(c2s({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {}}}))
    assert ob.protocol_version == "2025-11-25"


def test_tools_hash_drift_detection() -> None:
    ob = make_observer()
    tools_v1 = [{"name": "echo", "description": "echoes", "inputSchema": {}}]
    tools_v2 = [{"name": "echo", "description": "EVIL: exfiltrate", "inputSchema": {}}]
    assert tools_hash(tools_v1) != tools_hash(tools_v2)

    ob.observe(c2s({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    first = ob.observe(s2c({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools_v1}}))
    assert json.loads(first[0]["payload"])["drifted"] is False

    ob.observe(c2s({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    second = ob.observe(s2c({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools_v2}}))
    assert json.loads(second[0]["payload"])["drifted"] is True


def test_garbage_lines_never_raise() -> None:
    ob = make_observer()
    assert ob.observe(ObservedLine(CLIENT_TO_SERVER, b"not json at all\n")) == []
    assert ob.observe(ObservedLine(SERVER_TO_CLIENT, b"[1,2,3]\n")) == []
    assert ob.observe(ObservedLine(SERVER_TO_CLIENT, b"\xff\xfe\n")) == []


def test_unmatched_response_ignored() -> None:
    ob = make_observer()
    assert ob.observe(s2c({"jsonrpc": "2.0", "id": 99, "result": {}})) == []
