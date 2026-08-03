"""Cold-backup restore drill for the isolated single-node release topology."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

PROJECT = "abx-recovery-drill"
COMPOSE_FILE = "infra/compose.release.yml"
HELPER_IMAGE = (
    "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
)
VOLUMES = ("postgres_data", "clickhouse_data", "redis_data", "object_data")


def run(command: list[str], *, env: dict[str, str], capture: bool = False) -> str:
    result = subprocess.run(command, env=env, check=True, capture_output=capture, text=True)
    return result.stdout.strip() if capture else ""


def compose(arguments: list[str], *, env_file: str, env: dict[str, str]) -> str:
    return run(
        ["docker", "compose", "-p", PROJECT, "--env-file", env_file, "-f", COMPOSE_FILE]
        + arguments,
        env=env,
        capture=True,
    )


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    payload = json.dumps(body).encode() if body is not None else None
    outgoing = {"Content-Type": "application/json", **(headers or {})}
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                base_url + path, data=payload, headers=outgoing, method=method
            ),
            timeout=20,
        ) as response:
            return response.status, response.read()
    except HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path} returned {exc.code}: {detail}") from exc


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f"invalid environment line: {raw}")
        values[key] = value
    return values


def wait_ready(base_url: str, timeout: int = 90) -> None:
    last_error: Exception | None = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body = request(base_url, "/readyz")
            if status == 200 and json.loads(body)["status"] == "ready":
                return
        except Exception as exc:  # any failure means not ready yet
            last_error = exc
        time.sleep(2)
    raise RuntimeError(f"restored API did not become ready: {last_error}")


def archive_volumes(directory: Path, env: dict[str, str]) -> None:
    for name in VOLUMES:
        volume = f"{PROJECT}_{name}"
        run(
            [
                "docker", "run", "--rm", "--entrypoint", "tar",
                "-v", f"{volume}:/source:ro", "-v", f"{directory}:/backup",
                HELPER_IMAGE, "-C", "/source", "-czf", f"/backup/{name}.tar.gz", ".",
            ],
            env=env,
        )


def restore_volumes(directory: Path, env: dict[str, str]) -> None:
    for name in VOLUMES:
        volume = f"{PROJECT}_{name}"
        run(["docker", "volume", "create", volume], env=env)
        run(
            [
                "docker", "run", "--rm", "--entrypoint", "tar",
                "-v", f"{volume}:/target", "-v", f"{directory}:/backup:ro",
                HELPER_IMAGE, "-C", "/target", "-xzf", f"/backup/{name}.tar.gz",
            ],
            env=env,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", default="infra/release.env.example")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    env_path = Path(args.env_file).resolve()
    configured = read_env_file(env_path)
    admin_key = configured["ABX_ADMIN_KEY"]
    env = {
        **os.environ,
        "ABX_API_PORT": "18100",
        "ABX_WEB_PORT": "13100",
        "ABX_CORS_ORIGINS": "http://localhost:13100",
        "ABX_WEB_URL": "http://localhost:13100",
    }
    base_url = "http://127.0.0.1:18100"
    headers = {"X-ABX-Admin-Key": admin_key}
    compose(["down", "--volumes", "--remove-orphans"], env_file=str(env_path), env=env)
    try:
        up = ["up", "-d", "--wait"]
        up.append("--build" if not args.skip_build else "--no-build")
        compose(up, env_file=str(env_path), env=env)
        wait_ready(base_url)

        _, bootstrap_raw = request(
            base_url,
            "/v1/onboarding/bootstrap",
            method="POST",
            headers=headers,
            body={"user_ref": f"recovery-{uuid.uuid4()}", "tenant_name": "Recovery Drill"},
        )
        bootstrap = json.loads(bootstrap_raw)
        tenant_id = str(bootstrap["tenant_id"])
        ingest_token = str(bootstrap["ingest_token"])
        scan_token = str(bootstrap["scan_token"])
        session_id = f"restore-{uuid.uuid4()}"
        event_id = str(uuid.uuid4())
        request(
            base_url,
            "/v1/scans/local",
            method="POST",
            headers={"Authorization": f"Bearer {scan_token}"},
            body={
                "scope": "recovery-drill",
                "api_calls": 1,
                "findings": [{
                    "natural_key": f"aws:overpriv:{tenant_id}",
                    "finding_type": "over_privileged",
                    "severity": "critical",
                    "fingerprint": f"RECOVERY-{tenant_id[:8]}",
                    "owner": "arn:aws:iam::000000000000:user/recovery-agent",
                    "evidence": {
                        "reach_count": 1,
                        "reachable_resources": ["aws:s3:recovery-bucket"],
                    },
                    "remediation": "Replace wildcard access with a task-scoped role.",
                }],
            },
        )
        _, ingest_raw = request(
            base_url,
            "/v1/ingest",
            method="POST",
            headers={"Authorization": f"Bearer {ingest_token}"},
            body={
                "events": [{
                    "event_id": event_id,
                    "agent_id": "recovery-agent",
                    "session_id": session_id,
                    "seq": 0,
                    "ts": datetime.now(UTC).isoformat(),
                    "source": "mcp_tap",
                    "event_type": "file_op",
                    "operation": {
                        "name": "delete_recovery_marker",
                        "provider": "filesystem",
                        "target": "/recovery/marker",
                        "outcome": "success",
                        "duration_ms": 1,
                    },
                    "credential_ref": None,
                    "resource_refs": ["file:/recovery/marker"],
                    "payload": "recovery-drill-payload",
                }]
            },
        )
        if json.loads(ingest_raw)["accepted"] != 1:
            raise RuntimeError("recovery marker was not ingested")
        alert_deadline = time.monotonic() + 30
        alerts: list[dict[str, Any]] = []
        while time.monotonic() < alert_deadline:
            _, alerts_raw = request(
                base_url, f"/v1/alerts?tenant_id={tenant_id}", headers=headers
            )
            alerts = json.loads(alerts_raw)
            if any(item["rule_id"] == "destructive_operation" for item in alerts):
                break
            time.sleep(1)
        else:
            raise RuntimeError("alert worker did not produce the destructive-operation alert")
        compose(
            ["--profile", "maintenance", "run", "--rm", "--no-deps", "anchor"],
            env_file=str(env_path),
            env=env,
        )
        _, report_raw = request(
            base_url,
            f"/v1/reports/sessions/{urllib.parse.quote(session_id)}?tenant_id={tenant_id}",
            headers=headers,
        )
        report = json.loads(report_raw)
        report_ok = (
            report["session"]["session_id"] == session_id
            and report["verification"]["valid"]
            and report["markdown"].startswith("# Leaflyst Incident Report")
            and report["anchor_status"] == "matched"
        )
        if not report_ok:
            raise RuntimeError(
                "incident report acceptance failed: "
                f"session={report['session']['session_id']} "
                f"verification={report['verification']} anchor={report['anchor_status']}"
            )
        query = urllib.parse.urlencode({"tenant_id": tenant_id})
        _, evidence_before = request(base_url, f"/v1/evidence/tenant?{query}", headers=headers)
        footer = json.loads(evidence_before.decode().splitlines()[-1])
        trusted_anchor = str(footer["anchor"]["head_hash"])

        compose(
            ["kill", "api", "scanner-worker", "alert-worker"],
            env_file=str(env_path),
            env=env,
        )
        compose(
            [
                "up", "-d", "--no-build", "--wait",
                "api", "scanner-worker", "alert-worker",
            ],
            env_file=str(env_path),
            env=env,
        )
        wait_ready(base_url)
        _, replay_after_restart_raw = request(
            base_url,
            f"/v1/replay/sessions/{urllib.parse.quote(session_id)}?{query}",
            headers=headers,
        )
        replay_after_restart = json.loads(replay_after_restart_raw)
        if not any(
            item.get("event_id") == event_id
            for item in replay_after_restart["timeline"]
        ):
            raise RuntimeError("acknowledged event was lost across API/worker restart")
        _, alerts_after_restart_raw = request(
            base_url, f"/v1/alerts?tenant_id={tenant_id}", headers=headers
        )
        if not any(
            item["rule_id"] == "destructive_operation"
            for item in json.loads(alerts_after_restart_raw)
        ):
            raise RuntimeError("alert history was lost across API/worker restart")

        with tempfile.TemporaryDirectory(prefix="abx-recovery-") as temporary:
            backup_dir = Path(temporary).resolve()
            (backup_dir / "trusted-anchor.txt").write_text(trusted_anchor, encoding="ascii")
            compose(["stop"], env_file=str(env_path), env=env)
            archive_volumes(backup_dir, env)
            compose(["down", "--volumes"], env_file=str(env_path), env=env)
            restore_volumes(backup_dir, env)
            compose(["up", "-d", "--no-build", "--wait"], env_file=str(env_path), env=env)
            wait_ready(base_url)

            _, replay_raw = request(
                base_url,
                f"/v1/replay/sessions/{urllib.parse.quote(session_id)}?{query}",
                headers=headers,
            )
            replay = json.loads(replay_raw)
            recovered_ids = {
                item.get("event_id")
                for item in replay["timeline"]
                if item.get("kind") == "event"
            }
            if event_id not in recovered_ids:
                raise RuntimeError("restored event history is incomplete")
            _, alerts_after_raw = request(
                base_url, f"/v1/alerts?tenant_id={tenant_id}", headers=headers
            )
            if not any(
                item["rule_id"] == "destructive_operation"
                for item in json.loads(alerts_after_raw)
            ):
                raise RuntimeError("restored alert history is incomplete")
            _, evidence_after = request(
                base_url, f"/v1/evidence/tenant?{query}", headers=headers
            )
            evidence_path = backup_dir / "restored-evidence.ndjson"
            evidence_path.write_bytes(evidence_after)
            recovered_footer = json.loads(evidence_after.decode().splitlines()[-1])
            if recovered_footer["anchor"]["head_hash"] != trusted_anchor:
                raise RuntimeError("restored anchor differs from the external recovery control")
            anchor_ref = str(recovered_footer["anchor"]["ref"])
            anchor_key = anchor_ref.split("/", 3)[-1]
            retention_check = (
                "import os; from abx_api.settings import settings; "
                "from abx_api.store import s3_client; s3=s3_client(); "
                "key=os.environ['ABX_RECOVERED_ANCHOR_KEY']; "
                "versions=s3.list_object_versions(Bucket=settings.anchor_bucket, Prefix=key)"
                "['Versions']; "
                "latest=next(v for v in versions if v['Key']==key and v['IsLatest']); "
                "retention=s3.get_object_retention(Bucket=settings.anchor_bucket, Key=key, "
                "VersionId=latest['VersionId'])['Retention']; "
                "assert retention['Mode']=='COMPLIANCE'"
            )
            compose(
                [
                    "exec", "-T", "-e", f"ABX_RECOVERED_ANCHOR_KEY={anchor_key}",
                    "api", "python", "-c", retention_check,
                ],
                env_file=str(env_path),
                env=env,
            )
            run(
                [
                    sys.executable,
                    "tools/abx_verify.py",
                    str(evidence_path),
                    "--anchor-hash",
                    trusted_anchor,
                ],
                env=env,
            )
    except Exception:
        with contextlib.suppress(subprocess.CalledProcessError):
            print(
                compose(
                    ["logs", "--tail", "100", "api", "minio", "clickhouse"],
                    env_file=str(env_path),
                    env=env,
                ),
                file=sys.stderr,
            )
        raise
    finally:
        with contextlib.suppress(subprocess.CalledProcessError):
            compose(["down", "--volumes", "--remove-orphans"], env_file=str(env_path), env=env)
    print("OK: cold backup restored all durable stores and independently verified the chain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
