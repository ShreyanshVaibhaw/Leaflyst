"""Generate and verify release image provenance and CycloneDX SBOMs."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.parse
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_IMAGES = {
    "python": "agentblackbox-python:release-smoke",
    "web": "agentblackbox-web:release-smoke",
}
REVISION_LABEL = "org.opencontainers.image.revision"
NODE_INVENTORY = r"""
const fs = require('fs');
const roots = ['/app/node_modules'];
const seen = new Set();
const packages = new Map();
while (roots.length) {
  const current = roots.pop();
  let real;
  try { real = fs.realpathSync(current); } catch { continue; }
  if (seen.has(real)) continue;
  seen.add(real);
  let entries;
  try { entries = fs.readdirSync(real, {withFileTypes: true}); } catch { continue; }
  const manifest = `${real}/package.json`;
  try {
    const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8'));
    if (typeof pkg.name === 'string' && typeof pkg.version === 'string') {
      packages.set(`${pkg.name}\u0000${pkg.version}`, {name: pkg.name, version: pkg.version});
    }
  } catch {}
  for (const entry of entries) {
    if (entry.name !== '.bin' && (entry.isDirectory() || entry.isSymbolicLink())) {
      roots.push(`${real}/${entry.name}`);
    }
  }
}
process.stdout.write(JSON.stringify([...packages.values()]));
"""
PYTHON_INVENTORY = (
    "import importlib.metadata,json;"
    "print(json.dumps([{'name':d.metadata['Name'],'version':d.version} "
    "for d in importlib.metadata.distributions() if d.metadata['Name']]))"
)


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def git_commit() -> str:
    return run("git", "rev-parse", "HEAD")


def git_is_dirty() -> bool:
    return bool(run("git", "status", "--short"))


def inspect_image(image: str) -> dict[str, Any]:
    inspected = json.loads(run("docker", "image", "inspect", image))
    if len(inspected) != 1:
        raise RuntimeError(f"expected one image for {image}")
    data: dict[str, Any] = inspected[0]
    config = data.get("Config") or {}
    labels = config.get("Labels") or {}
    return {
        "tag": image,
        "image_id": data["Id"],
        "repo_digests": sorted(data.get("RepoDigests") or []),
        "created": data.get("Created"),
        "platform": f"{data.get('Os', 'unknown')}/{data.get('Architecture', 'unknown')}",
        "user": config.get("User") or "root",
        "revision": labels.get(REVISION_LABEL),
    }


def language_packages(kind: str, image: str) -> list[dict[str, str]]:
    if kind == "python":
        raw = run("docker", "run", "--rm", "--entrypoint", "python", image, "-c", PYTHON_INVENTORY)
        ecosystem = "pypi"
    else:
        raw = run("docker", "run", "--rm", "--entrypoint", "node", image, "-e", NODE_INVENTORY)
        ecosystem = "npm"
    return [
        {"ecosystem": ecosystem, "name": item["name"], "version": item["version"]}
        for item in json.loads(raw)
    ]


def os_packages(image: str) -> list[dict[str, str]]:
    output = run(
        "docker",
        "run",
        "--rm",
        "--entrypoint",
        "dpkg-query",
        image,
        "-W",
        "-f=${Package}\\t${Version}\\n",
    )
    packages: list[dict[str, str]] = []
    for line in output.splitlines():
        name, version = line.split("\t", 1)
        packages.append({"ecosystem": "deb", "name": name, "version": version})
    return packages


def purl(component: dict[str, str]) -> str:
    ecosystem = component["ecosystem"]
    raw_name = component["name"]
    if ecosystem == "npm" and raw_name.startswith("@") and "/" in raw_name:
        namespace, package_name = raw_name.split("/", 1)
        encoded_namespace = urllib.parse.quote(namespace, safe="")
        encoded_name = urllib.parse.quote(package_name, safe="")
        name = f"{encoded_namespace}/{encoded_name}"
    else:
        if ecosystem == "pypi":
            raw_name = raw_name.lower().replace("_", "-").replace(".", "-")
        name = urllib.parse.quote(raw_name, safe="")
    version = urllib.parse.quote(component["version"], safe="")
    if ecosystem == "deb":
        return f"pkg:deb/debian/{name}@{version}"
    return f"pkg:{ecosystem}/{name}@{version}"


def make_sbom(kind: str, image: dict[str, Any], commit: str) -> dict[str, Any]:
    packages = os_packages(image["tag"]) + language_packages(kind, image["tag"])
    unique = {(item["ecosystem"], item["name"], item["version"]): item for item in packages}
    components = []
    for item in sorted(unique.values(), key=lambda value: tuple(value.values())):
        ref = purl(item)
        components.append(
            {
                "type": "library",
                "name": item["name"],
                "version": item["version"],
                "purl": ref,
                "bom-ref": ref,
                "properties": [{"name": "abx:ecosystem", "value": item["ecosystem"]}],
            }
        )
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{image['image_id']}:{commit}")
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": image["created"],
            "component": {
                "type": "container",
                "name": image["tag"],
                "version": image["image_id"],
                "bom-ref": image["image_id"],
                "properties": [
                    {"name": "abx:git_commit", "value": commit},
                    {"name": "abx:platform", "value": image["platform"]},
                ],
            },
        },
        "components": components,
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate(output: Path, images: dict[str, str], require_clean: bool) -> Path:
    commit = git_commit()
    dirty = git_is_dirty()
    if require_clean and dirty:
        raise RuntimeError("refusing to generate release provenance from a dirty checkout")
    output.mkdir(parents=True, exist_ok=True)
    records: dict[str, Any] = {}
    for kind, tag in images.items():
        image = inspect_image(tag)
        if image["revision"] != commit:
            message = (
                f"{tag} revision label is {image['revision']!r}, "
                f"expected checked-out commit {commit}"
            )
            raise RuntimeError(message)
        sbom_path = output / f"{kind}.cdx.json"
        write_json(sbom_path, make_sbom(kind, image, commit))
        records[kind] = {**image, "sbom": sbom_path.name, "sbom_sha256": sha256(sbom_path)}
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "git_commit": commit,
        "git_dirty": dirty,
        "images": records,
    }
    path = output / "release-manifest.json"
    write_json(path, manifest)
    return path


def verify(path: Path) -> None:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise RuntimeError("unsupported release manifest schema")
    for kind, expected in manifest["images"].items():
        actual = inspect_image(expected["tag"])
        if actual["image_id"] != expected["image_id"]:
            raise RuntimeError(f"{kind} image ID no longer matches the release manifest")
        if actual["revision"] != manifest["git_commit"]:
            raise RuntimeError(f"{kind} image revision no longer matches the release manifest")
        sbom_path = path.parent / expected["sbom"]
        if sha256(sbom_path) != expected["sbom_sha256"]:
            raise RuntimeError(f"{kind} SBOM hash no longer matches the release manifest")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("release-artifacts"))
    parser.add_argument("--python-image", default=DEFAULT_IMAGES["python"])
    parser.add_argument("--web-image", default=DEFAULT_IMAGES["web"])
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--verify", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify:
            verify(args.verify)
            print(f"OK: verified release provenance in {args.verify}")
        else:
            path = generate(
                args.output,
                {"python": args.python_image, "web": args.web_image},
                args.require_clean,
            )
            print(f"OK: wrote release provenance to {path}")
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
