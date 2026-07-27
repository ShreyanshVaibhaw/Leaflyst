"""Generate and verify release image provenance and CycloneDX SBOMs."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_IMAGES = {
    "python": "leaflyst-python:release-smoke",
    "web": "leaflyst-web:release-smoke",
}
REVISION_LABEL = "org.opencontainers.image.revision"


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


def generate_sbom(syft: str, image: str, path: Path) -> None:
    run(syft, image, "-o", f"cyclonedx-json={path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX":
        raise RuntimeError(f"Syft did not produce a CycloneDX SBOM for {image}")
    if not document.get("components"):
        raise RuntimeError(f"Syft produced an empty SBOM for {image}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate(output: Path, images: dict[str, str], require_clean: bool, syft: str = "syft") -> Path:
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
        generate_sbom(syft, image["tag"], sbom_path)
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
    parser.add_argument("--syft", default="syft", help="path to the Syft executable")
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
                args.syft,
            )
            print(f"OK: wrote release provenance to {path}")
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
