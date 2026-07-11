"""Byte-faithful stdio pump (blueprint 5.1).

Spawns the real MCP server as a child process and pumps newline-delimited
JSON-RPC both ways, passing the ORIGINAL bytes through untouched. A copy of
each line goes to an observation queue; parsing happens off the hot path so
forwarding latency stays low. Unparseable lines still pass through.

Rules enforced here:
- stdout carries MCP traffic exclusively; the tap never writes diagnostics
  to it (diagnostics go to stderr / the spool dir).
- Child stderr is forwarded to our stderr (clients surface it in their logs).
- No traffic is injected, ever; initialize/initialized pass through verbatim.
- Lifecycle: client closes our stdin -> close child stdin -> wait -> exit
  with the child's code. Tap failure mode is always "agent keeps working,
  recording degrades" - observation errors are swallowed, never propagated.

Threads (not asyncio): Windows asyncio cannot read console stdin pipes;
threads are simple and portable.
"""

from __future__ import annotations

import contextlib
import queue
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass

# Direction tags for observed lines.
CLIENT_TO_SERVER = "c2s"
SERVER_TO_CLIENT = "s2c"


@dataclass
class ObservedLine:
    direction: str
    raw: bytes


def run_pump(
    command: list[str],
    observe: queue.Queue[ObservedLine | None],
    max_observe_queue: int = 10_000,
) -> int:
    """Run the child MCP server, pumping stdio until EOF. Returns exit code.

    Observed lines are put on `observe` (None is enqueued at shutdown as a
    sentinel). If the queue is full the line is dropped - recording degrades,
    the agent never blocks.
    """
    # Windows: CreateProcess does not resolve "npx" -> "npx.cmd"; which() does.
    resolved = shutil.which(command[0]) or command[0]
    child = subprocess.Popen(
        [resolved, *command[1:]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,  # unbuffered: forward immediately
    )
    assert child.stdin is not None and child.stdout is not None and child.stderr is not None
    child_in, child_out, child_err = child.stdin, child.stdout, child.stderr

    def _observe(direction: str, raw: bytes) -> None:
        # Backpressure guard: full queue -> drop the observation, never block.
        with contextlib.suppress(queue.Full):
            observe.put_nowait(ObservedLine(direction, raw))

    def pump_in() -> None:
        """our stdin -> child stdin (client -> server)."""
        try:
            for line in sys.stdin.buffer:
                child_in.write(line)
                child_in.flush()
                _observe(CLIENT_TO_SERVER, line)
        except (BrokenPipeError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                child_in.close()

    def pump_out() -> None:
        """child stdout -> our stdout (server -> client)."""
        try:
            for line in child_out:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
                _observe(SERVER_TO_CLIENT, line)
        except (BrokenPipeError, OSError):
            pass

    def pump_err() -> None:
        """child stderr -> our stderr, chunked (not line-based: logs vary)."""
        try:
            while chunk := child_err.read(4096):
                sys.stderr.buffer.write(chunk)
                sys.stderr.buffer.flush()
        except (BrokenPipeError, OSError):
            pass

    threads = [
        threading.Thread(target=pump_in, daemon=True),
        threading.Thread(target=pump_out, daemon=True),
        threading.Thread(target=pump_err, daemon=True),
    ]
    for t in threads:
        t.start()

    code = child.wait()
    # Give output pumps a moment to flush trailing lines, then signal shutdown.
    threads[1].join(timeout=2)
    threads[2].join(timeout=2)
    observe.put(None)
    return code
