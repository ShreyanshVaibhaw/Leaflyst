"""abx-tap CLI.

    abx-tap run --agent NAME [--server-name NAME] -- <server command...>
    abx-tap install --client claude-code|claude-desktop|cursor --agent NAME
                    [--ingest-url URL] [--token TOKEN] [--dir PATH]
    abx-tap uninstall --client ... [--dir PATH]

Ingest URL/token come from flags or ABX_INGEST_URL / ABX_INGEST_TOKEN env.
Without them the tap still proxies; events spool locally only (the agent is
never blocked on recording).
"""

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
from pathlib import Path

from abx_tap.config_install import install, uninstall
from abx_tap.emitter import Emitter
from abx_tap.observer import Observer
from abx_tap.pump import ObservedLine, run_pump


def _run(args: argparse.Namespace) -> int:
    if not args.command:
        print("abx-tap run: missing server command after --", file=sys.stderr)
        return 2
    ingest_url = args.ingest_url or os.environ.get("ABX_INGEST_URL")
    token = args.token or os.environ.get("ABX_INGEST_TOKEN")

    observer = Observer(agent_id=args.agent, server_name=args.server_name or args.command[0])
    emitter = Emitter(ingest_url, token)
    emitter.start()

    observe_q: queue.Queue[ObservedLine | None] = queue.Queue(maxsize=10_000)

    def observe_loop() -> None:
        while (line := observe_q.get()) is not None:
            for event in observer.observe(line):
                emitter.emit(event)

    observer_thread = threading.Thread(target=observe_loop, daemon=True)
    observer_thread.start()

    code = run_pump(args.command, observe_q)

    observer_thread.join(timeout=2)
    emitter.close()
    return code


def _install(args: argparse.Namespace) -> int:
    ingest_url = args.ingest_url or os.environ.get("ABX_INGEST_URL")
    token = args.token or os.environ.get("ABX_INGEST_TOKEN")
    directory = Path(args.dir) if args.dir else None
    try:
        wrapped, backup = install(args.client, args.agent, ingest_url, token, directory)
    except FileNotFoundError as e:
        print(f"no config found for {args.client}: {e.filename}", file=sys.stderr)
        return 1
    if wrapped:
        print(f"wrapped {wrapped} server(s); backup at {backup}")
    else:
        print("nothing to wrap (no stdio servers, or already wrapped)")
    return 0


def _uninstall(args: argparse.Namespace) -> int:
    directory = Path(args.dir) if args.dir else None
    if uninstall(args.client, directory):
        print("restored original config from backup")
        return 0
    print("no backup found; nothing restored", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="abx-tap")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="proxy a stdio MCP server, recording traffic")
    run_p.add_argument("--agent", required=True)
    run_p.add_argument("--server-name", default=None)
    run_p.add_argument("--ingest-url", default=None)
    run_p.add_argument("--token", default=None)
    run_p.add_argument("command", nargs=argparse.REMAINDER,
                       help="server command after --")

    for name in ("install", "uninstall"):
        p = sub.add_parser(name)
        p.add_argument("--client", required=True,
                       choices=["claude-code", "claude-desktop", "cursor"])
        p.add_argument("--dir", default=None,
                       help="project dir for claude-code (default: cwd)")
        if name == "install":
            p.add_argument("--agent", required=True)
            p.add_argument("--ingest-url", default=None)
            p.add_argument("--token", default=None)

    args = parser.parse_args()
    if args.cmd == "run" and args.command and args.command[0] == "--":
        args.command = args.command[1:]

    match args.cmd:
        case "run":
            return _run(args)
        case "install":
            return _install(args)
        case "uninstall":
            return _uninstall(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
