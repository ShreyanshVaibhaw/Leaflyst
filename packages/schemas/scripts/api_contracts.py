from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from abx_api.main import app

ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = ROOT / "apps" / "api" / "openapi.json"
TS_PATH = ROOT / "apps" / "web" / "src" / "lib" / "generated" / "api-contracts.ts"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate API contracts from FastAPI OpenAPI")
    parser.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = parser.parse_args()

    openapi = app.openapi()
    openapi_text = json.dumps(openapi, indent=2, sort_keys=True) + "\n"
    ts_text = _typescript_contracts(openapi)

    outputs = {OPENAPI_PATH: openapi_text, TS_PATH: ts_text}
    if args.check:
        stale = [
            path
            for path, text in outputs.items()
            if not path.exists() or path.read_text() != text
        ]
        if stale:
            for path in stale:
                print(f"stale generated contract: {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        return 0

    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return 0


def _typescript_contracts(openapi: dict[str, Any]) -> str:
    schemas = openapi.get("components", {}).get("schemas", {})
    lines = [
        "/* Generated from FastAPI OpenAPI. Do not edit by hand. */",
        "",
    ]
    for name in sorted(schemas):
        lines.append(f"export type {name} = {_ts_type(schemas[name])};")
        lines.append("")
    return "\n".join(lines)


def _ts_type(schema: dict[str, Any]) -> str:
    if "$ref" in schema:
        return _ref_name(str(schema["$ref"]))
    if "const" in schema:
        return _literal(schema["const"])
    if "allOf" in schema:
        return " & ".join(_ts_type(item) for item in schema["allOf"])
    if "oneOf" in schema:
        return " | ".join(_ts_type(item) for item in schema["oneOf"])
    if "anyOf" in schema:
        return " | ".join(_ts_type(item) for item in schema["anyOf"])
    if "enum" in schema:
        return " | ".join(_literal(value) for value in schema["enum"])

    value_type = schema.get("type")
    if value_type == "null":
        return "null"
    if isinstance(value_type, list):
        return " | ".join(_ts_type({"type": item}) for item in value_type)

    if value_type == "array":
        item_type = _ts_type(schema.get("items", {}))
        return f"Array<{item_type}>"
    if value_type == "object" or "properties" in schema:
        return _object_type(schema)
    if value_type in {"integer", "number"}:
        return "number"
    if value_type == "boolean":
        return "boolean"
    if value_type == "string":
        return "string"
    return "unknown"


def _object_type(schema: dict[str, Any]) -> str:
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    additional = schema.get("additionalProperties")
    parts: list[str] = []
    for name, prop_schema in sorted(properties.items()):
        optional = "" if name in required or "const" in prop_schema else "?"
        parts.append(f"{_prop(name)}{optional}: {_ts_type(prop_schema)}")
    if additional:
        value_type = _ts_type(additional) if isinstance(additional, dict) else "unknown"
        parts.append(f"[key: string]: {value_type}")
    if not parts:
        return "Record<string, unknown>"
    return "{ " + "; ".join(parts) + " }"


def _ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def _prop(name: str) -> str:
    return name if name.isidentifier() else json.dumps(name)


def _literal(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(str(value))


if __name__ == "__main__":
    raise SystemExit(main())
