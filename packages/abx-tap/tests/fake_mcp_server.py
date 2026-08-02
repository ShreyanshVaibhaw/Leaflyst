"""Minimal DUAL-ERA stdio MCP server for tap tests: newline-delimited JSON-RPC.

Legacy (<= 2025-11-25): initialize handshake, tools/list, tools/call (echo),
resources/read, one notification after initialize, error on unknown methods.

Modern (>= 2026-07-28): no handshake. server/discover, per-request `_meta`,
`resultType` on every result, serverInfo in result `_meta`.

Era is selected per request exactly as the spec prescribes for a dual-era
server: a request carrying modern per-request `_meta` is served modern, an
`initialize` request selects legacy. This keeps legacy responses byte-identical
to what they were before modern support existed.

Set FAKE_TOOLS_DESC to vary the tool description (drift testing).
"""

import json
import os
import sys

PROTOCOL_MODERN = "2026-07-28"
PROTOCOL_LEGACY = "2025-11-25"
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
SERVER_INFO = {"name": "fake", "version": "1.0"}

TOOLS = [
    {
        "name": "echo",
        "description": os.environ.get("FAKE_TOOLS_DESC", "echoes input"),
        "inputSchema": {"type": "object"},
    },
    {"name": "read_file", "description": "reads a file", "inputSchema": {"type": "object"}},
]


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def is_modern(msg: dict) -> bool:
    """A request carrying modern per-request `_meta` is served statelessly."""
    params = msg.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    return isinstance(meta, dict) and META_PROTOCOL_VERSION in meta


def send_modern(msg_id, result: dict) -> None:
    """Modern results carry resultType and self-reported server identity."""
    send({
        "jsonrpc": "2.0", "id": msg_id,
        "result": {"resultType": "complete", "_meta": {META_SERVER_INFO: SERVER_INFO}, **result},
    })


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")

        if is_modern(msg) or method == "server/discover":
            if method == "server/discover":
                send_modern(msg_id, {
                    "supportedVersions": [PROTOCOL_MODERN, PROTOCOL_LEGACY],
                    "capabilities": {"tools": {}},
                    "ttlMs": 3600000,
                    "cacheScope": "public",
                })
            elif method == "tools/list":
                send_modern(msg_id, {"tools": TOOLS, "ttlMs": 3600000, "cacheScope": "public"})
            elif method == "tools/call":
                args = msg.get("params", {}).get("arguments", {})
                send_modern(msg_id, {"content": [{"type": "text", "text": json.dumps(args)}]})
            elif method == "initialize":
                # Legacy clients have no fall-forward mechanism, so a
                # modern-only answer names the versions it does support.
                send({
                    "jsonrpc": "2.0", "id": msg_id,
                    "error": {
                        "code": -32022, "message": "Unsupported protocol version",
                        "data": {"supported": [PROTOCOL_MODERN],
                                 "requested": msg.get("params", {}).get("protocolVersion")},
                    },
                })
            elif msg_id is not None:
                send({"jsonrpc": "2.0", "id": msg_id,
                      "error": {"code": -32601, "message": "method not found"}})
            continue

        if method == "initialize":
            send({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "1.0"},
                },
            })
            send({"jsonrpc": "2.0", "method": "notifications/initialized-ack"})
        elif method == "notifications/initialized":
            pass  # notification, no response
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            args = msg.get("params", {}).get("arguments", {})
            send({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {"content": [{"type": "text", "text": json.dumps(args)}]},
            })
        elif method == "resources/read":
            send({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {"contents": [{"uri": msg["params"]["uri"], "text": "data"}]},
            })
        elif msg_id is not None:
            send({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": "method not found"},
            })


if __name__ == "__main__":
    main()
