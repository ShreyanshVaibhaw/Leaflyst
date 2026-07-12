from datetime import UTC, datetime, timedelta

from abx_scanner.aws import AccessKey, AwsScanResult, Principal
from abx_scanner.local import build_upload, upload_findings
from abx_scanner.policy import parse_policy_document


def test_local_scan_upload_contains_findings_only() -> None:
    now = datetime.now(UTC)
    result = AwsScanResult(
        "123456789012",
        [
            Principal(
                kind="iam_user",
                name="bot",
                arn="arn:aws:iam::123456789012:user/bot",
                access_keys=[
                    AccessKey("AKIAFINGERPRINT", now - timedelta(days=180), None, "Active")
                ],
                policies=[
                    parse_policy_document(
                        "admin",
                        {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ]
                        },
                    )
                ],
            )
        ],
        9,
    )

    upload = build_upload(result)
    serialized = str(upload)
    assert upload["api_calls"] == 9
    assert {item["finding_type"] for item in upload["findings"]} == {
        "orphaned_credential",
        "over_privileged",
        "stale_authorization",
        "blast_radius",
    }
    assert "AKIAFINGERPRINT" in serialized
    assert "secret_access_key" not in serialized
    assert "policy_document" not in serialized


def test_local_upload_rejects_cleartext_remote_endpoint() -> None:
    try:
        upload_findings("http://example.com", "abx_scan_secret", {"findings": []})
    except ValueError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("cleartext remote upload was accepted")
