"""Install/uninstall the tap into MCP client configs (blueprint 5.1).

Wraps every stdio server entry so the client launches `abx-tap run -- <orig>`
instead of the server directly. A timestamped byte-exact backup is written
next to the config before any rewrite; uninstall restores the newest backup.

Supported clients and config locations:
- claude-code:     .mcp.json in the target directory (project-scoped)
- claude-desktop:  platform-specific claude_desktop_config.json
- cursor:          ~/.cursor/mcp.json

Servers with a "url" (remote/HTTP) are skipped: v0.1 taps stdio only; remote
servers are reachable by tapping the stdio side of an mcp-remote bridge.
Already-wrapped servers are skipped (idempotent install).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

BACKUP_SUFFIX = ".abx-backup-"


def config_path(client: str, directory: Path | None = None) -> Path:
    home = Path.home()
    match client:
        case "claude-code":
            return (directory or Path.cwd()) / ".mcp.json"
        case "claude-desktop":
            if sys.platform == "win32":
                return Path(os.environ["APPDATA"]) / "Claude" / "claude_desktop_config.json"
            if sys.platform == "darwin":
                return (
                    home / "Library" / "Application Support" / "Claude"
                    / "claude_desktop_config.json"
                )
            return home / ".config" / "Claude" / "claude_desktop_config.json"
        case "cursor":
            return home / ".cursor" / "mcp.json"
        case _:
            raise ValueError(f"unknown client: {client}")


def _is_wrapped(entry: dict[str, object]) -> bool:
    return "abx-tap" in str(entry.get("command", ""))


def _wrap(
    name: str,
    entry: dict[str, object],
    agent: str,
    ingest_url: str | None,
    token: str | None,
) -> dict[str, object]:
    orig_args = entry.get("args") or []
    assert isinstance(orig_args, list)
    args: list[object] = ["run", "--agent", agent, "--server-name", name]
    args += ["--", entry["command"], *orig_args]
    wrapped = {**entry, "command": "abx-tap", "args": args}
    if ingest_url or token:
        orig_env = entry.get("env") or {}
        assert isinstance(orig_env, dict)
        env = dict(orig_env)
        if ingest_url:
            env["ABX_INGEST_URL"] = ingest_url
        if token:
            env["ABX_INGEST_TOKEN"] = token
        wrapped["env"] = env
    return wrapped


def install(
    client: str,
    agent: str,
    ingest_url: str | None,
    token: str | None,
    directory: Path | None = None,
) -> tuple[int, Path]:
    """Wrap all stdio servers. Returns (wrapped count, backup path)."""
    path = config_path(client, directory)
    original = path.read_bytes()  # raises if missing: nothing to install into
    config = json.loads(original)
    servers = config.get("mcpServers", {})

    wrapped = 0
    for name, entry in servers.items():
        if not isinstance(entry, dict) or "command" not in entry:
            continue  # url-based/remote or malformed: skip
        if _is_wrapped(entry):
            continue
        servers[name] = _wrap(name, entry, agent, ingest_url, token)
        wrapped += 1

    backup = path.with_name(path.name + BACKUP_SUFFIX + str(time.time_ns()))
    if wrapped:
        backup.write_bytes(original)
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return wrapped, backup


def uninstall(client: str, directory: Path | None = None) -> bool:
    """Restore the newest backup byte-for-byte. Returns True if restored."""
    path = config_path(client, directory)
    backups = sorted(path.parent.glob(path.name + BACKUP_SUFFIX + "*"))
    if not backups:
        return False
    newest = backups[-1]
    path.write_bytes(newest.read_bytes())
    for b in backups:
        b.unlink()
    return True
