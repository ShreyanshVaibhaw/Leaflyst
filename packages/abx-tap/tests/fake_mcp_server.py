"""Minimal stdio MCP server for tap tests: newline-delimited JSON-RPC.

Responds to initialize, tools/list, tools/call (echo), resources/read.
Sends one notification after initialize. Unknown methods get an error.
Set FAKE_TOOLS_DESC to vary the tool description (drift testing).
"""

import json
import os
import sys

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


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
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
