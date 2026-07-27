from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from abx_api.main import app

ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = ROOT / "apps" / "api" / "openapi.json"
TS_PATH = ROOT / "apps" / "web" / "src" / "lib" / "generated" / "api-contracts.ts"
OPENAPI_TYPESCRIPT = "openapi-typescript@7.13.0"


def generate_typescript(openapi_text: str) -> str:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "openapi.json"
        output = Path(directory) / "api-contracts.ts"
        source.write_text(openapi_text, encoding="utf-8")
        subprocess.run(
            ["pnpm", "dlx", OPENAPI_TYPESCRIPT, str(source), "-o", str(output)],
            check=True,
            cwd=ROOT,
            shell=(sys.platform == "win32"),
        )
        return output.read_text(encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate API contracts from FastAPI OpenAPI")
    parser.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = parser.parse_args()

    openapi = app.openapi()
    openapi_text = json.dumps(openapi, indent=2, sort_keys=True) + "\n"
    ts_text = generate_typescript(openapi_text)

    outputs = {OPENAPI_PATH: openapi_text, TS_PATH: ts_text}
    if args.check:
        stale = [
            path
            for path, text in outputs.items()
            if not path.exists() or path.read_text(encoding="utf-8") != text
        ]
        if stale:
            for path in stale:
                print(f"stale generated contract: {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        return 0

    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
