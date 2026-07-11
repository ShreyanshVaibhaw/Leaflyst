import json
from pathlib import Path

from abx_tap.config_install import install, uninstall

CONFIG = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
            "env": {"FOO": "bar"},
        },
        "remote-thing": {"url": "https://example.com/mcp"},
    }
}


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(CONFIG, indent=2), encoding="utf-8")
    return path


def test_install_wraps_stdio_only(tmp_path: Path) -> None:
    write_config(tmp_path)
    wrapped, backup = install(
        "claude-code", "my-agent", "http://localhost:8000", "abx_ingest_x", tmp_path
    )
    assert wrapped == 1
    assert backup.exists()

    config = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    fs = config["mcpServers"]["filesystem"]
    assert fs["command"] == "abx-tap"
    assert fs["args"][:5] == ["run", "--agent", "my-agent", "--server-name", "filesystem"]
    assert fs["args"][5] == "--"
    assert fs["args"][6:] == ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    assert fs["env"]["ABX_INGEST_URL"] == "http://localhost:8000"
    assert fs["env"]["ABX_INGEST_TOKEN"] == "abx_ingest_x"
    assert fs["env"]["FOO"] == "bar"  # original env preserved
    # Remote server untouched.
    assert config["mcpServers"]["remote-thing"] == {"url": "https://example.com/mcp"}


def test_install_idempotent(tmp_path: Path) -> None:
    write_config(tmp_path)
    install("claude-code", "a", None, None, tmp_path)
    wrapped, _ = install("claude-code", "a", None, None, tmp_path)
    assert wrapped == 0  # second run wraps nothing


def test_uninstall_restores_byte_identical(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    original = path.read_bytes()
    install("claude-code", "a", "http://x", "t", tmp_path)
    assert path.read_bytes() != original
    assert uninstall("claude-code", tmp_path)
    assert path.read_bytes() == original  # exit criterion: byte-identical
    assert not list(tmp_path.glob("*.abx-backup-*"))  # backups cleaned


def test_uninstall_without_backup(tmp_path: Path) -> None:
    write_config(tmp_path)
    assert not uninstall("claude-code", tmp_path)
