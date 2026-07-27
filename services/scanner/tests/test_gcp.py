"""Google Cloud scanner tests with a fully mocked GET-only REST boundary."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from abx_scanner.db import connect
from abx_scanner.gcp import enumerate_project
from abx_scanner.gcp_client import IAM_ROOT, GcpClient, Response
from abx_scanner.readonly import ReadOnlyViolation
from abx_scanner.scan import run_gcp_scan


def _pg_up() -> bool:
    try:
        with connect():
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _pg_up(), reason="postgres dev stack not running")

PROJECT = "pocketos-prod"
SERVICE_ACCOUNT = f"svc-agent@{PROJECT}.iam.gserviceaccount.com"
READER_ACCOUNT = f"audit-reader@{PROJECT}.iam.gserviceaccount.com"


def _iso(days_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat().replace(
        "+00:00", "Z"
    )


def _response(value: object) -> Response:
    return Response(200, json.dumps(value).encode())


def make_client() -> GcpClient:
    def opener(url: str) -> Response:
        parsed = urlparse(url)
        if parsed.netloc == "iam.googleapis.com" and parsed.path.endswith(
            "/serviceAccounts"
        ):
            return _response(
                {
                    "accounts": [
                        {"email": SERVICE_ACCOUNT, "uniqueId": "1001"},
                        {"email": READER_ACCOUNT, "uniqueId": "1002"},
                    ]
                }
            )
        if parsed.netloc == "iam.googleapis.com" and SERVICE_ACCOUNT in parsed.path:
            return _response(
                {
                    "keys": [
                        {
                            "name": (
                                f"projects/{PROJECT}/serviceAccounts/"
                                f"{SERVICE_ACCOUNT}/keys/key-old"
                            ),
                            "validAfterTime": _iso(200),
                            "validBeforeTime": _iso(-100),
                            "keyAlgorithm": "KEY_ALG_RSA_2048",
                            "keyOrigin": "GOOGLE_PROVIDED",
                            "privateKeyData": "MUST-NOT-BE-STORED",
                        },
                        {
                            "name": (
                                f"projects/{PROJECT}/serviceAccounts/"
                                f"{SERVICE_ACCOUNT}/keys/key-off"
                            ),
                            "validAfterTime": _iso(5),
                            "disabled": True,
                        },
                    ]
                }
            )
        if parsed.netloc == "iam.googleapis.com" and READER_ACCOUNT in parsed.path:
            return _response({"keys": []})
        if parsed.netloc == "cloudasset.googleapis.com":
            query = parse_qs(parsed.query).get("query", [""])[0]
            email = SERVICE_ACCOUNT if SERVICE_ACCOUNT in query else READER_ACCOUNT
            roles = (
                ["roles/owner", "roles/storage.objectViewer"]
                if email == SERVICE_ACCOUNT
                else ["roles/viewer"]
            )
            return _response(
                {
                    "results": [
                        {
                            "resource": f"//cloudresourcemanager.googleapis.com/projects/{PROJECT}",
                            "assetType": "cloudresourcemanager.googleapis.com/Project",
                            "policy": {
                                "bindings": [
                                    {
                                        "role": role,
                                        "members": [f"serviceAccount:{email}"],
                                    }
                                    for role in roles
                                ]
                            },
                        }
                    ]
                }
            )
        return Response(404, b"not found")

    return GcpClient(opener=opener)


def test_enumeration_is_get_only_and_discards_key_material() -> None:
    client = make_client()
    result = enumerate_project(client, PROJECT)
    assert len(result.service_accounts) == 2
    assert [key.fingerprint for key in result.service_accounts[0].keys] == [
        "gcpkey:key-old",
        "gcpkey:key-off",
    ]
    assert result.service_accounts[0].grants[0].access == "admin"
    assert any("last-used" in note for note in result.notes)
    assert "MUST-NOT-BE-STORED" not in repr(result)
    assert client.counter.count == 5
    with pytest.raises(ReadOnlyViolation):
        client._request("DELETE", IAM_ROOT, "/v1/projects/x/serviceAccounts/y")
    with pytest.raises(ValueError):
        client._request("GET", "https://example.com", "/v1/projects/x")


def test_gcp_scan_persists_fingerprints_reach_and_findings(tenant: str) -> None:
    summary = run_gcp_scan(tenant, PROJECT, make_client())
    assert summary.account_id == PROJECT
    assert summary.principals == 2
    assert summary.credentials == 2
    assert summary.findings == 5
    assert summary.api_calls == 5

    with connect() as conn:
        credentials = conn.execute(
            "SELECT fingerprint, status FROM credentials "
            "WHERE tenant_id=%s AND provider='gcp' ORDER BY fingerprint",
            (tenant,),
        ).fetchall()
        findings = conn.execute(
            "SELECT natural_key FROM findings WHERE tenant_id=%s "
            "AND natural_key LIKE 'gcp:%%' ORDER BY natural_key",
            (tenant,),
        ).fetchall()
        stored = conn.execute(
            "SELECT string_agg(raw::text, ' ') FROM permissions "
            "WHERE tenant_id=%s AND provider='gcp'",
            (tenant,),
        ).fetchone()[0]
        permission_count = conn.execute(
            "SELECT count(*) FROM permissions WHERE tenant_id=%s AND provider='gcp'",
            (tenant,),
        ).fetchone()[0]
    assert credentials == [("gcpkey:key-off", "inactive"), ("gcpkey:key-old", "active")]
    assert "gcp:overpriv:gcpkey:key-old" in {row[0] for row in findings}
    assert "MUST-NOT-BE-STORED" not in stored

    run_gcp_scan(tenant, PROJECT, make_client())
    with connect() as conn:
        rescanned_count = conn.execute(
            "SELECT count(*) FROM permissions WHERE tenant_id=%s AND provider='gcp'",
            (tenant,),
        ).fetchone()[0]
    assert permission_count == rescanned_count
