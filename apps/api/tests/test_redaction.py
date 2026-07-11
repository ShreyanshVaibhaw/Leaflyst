"""Redaction corpus: every seeded secret must be scrubbed (Phase 1 exit criterion)."""

from abx_api.redaction import redact, redact_and_truncate

# (name, text containing a secret, the secret substring that must vanish)
CORPUS = [
    (
        "aws access key id",
        "creds: AKIAIOSFODNN7EXAMPLE region us-east-1",
        "AKIAIOSFODNN7EXAMPLE",
    ),
    (
        "aws secret in env assignment",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY done",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    (
        "github classic pat",
        "cloning with ghp_16C7e42F292c6912E7710c838347Ae178B4a here",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ),
    (
        "github fine grained pat",
        "token github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV ok",
        "github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV",
    ),
    (
        "slack bot token",
        "posting via xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
        "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    ),
    (
        "jwt",
        "auth eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ),
    (
        "pem private key",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7bq0\nmore\n"
        "-----END RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA7bq0",
    ),
    (
        "authorization header",
        '{"Authorization": "Bearer sk-live-abcDEF123456789_secretvalue"}',
        "sk-live-abcDEF123456789_secretvalue",
    ),
    (
        "postgres connection string",
        "dsn postgresql://svc_agent:sup3rS3cretPW@db.internal:5432/prod",
        "sup3rS3cretPW",
    ),
    (
        "generic api key assignment",
        "OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmn",
        "sk-proj-1234567890abcdefghijklmn",
    ),
]


def test_every_corpus_secret_is_scrubbed() -> None:
    for name, text, secret in CORPUS:
        scrubbed, fired = redact(text)
        assert secret not in scrubbed, f"{name}: secret survived redaction"
        assert fired, f"{name}: no rule fired"
        assert "[REDACTED:" in scrubbed, f"{name}: no redaction marker"


def test_last4_marker_preserved_for_correlation() -> None:
    scrubbed, _ = redact("creds: AKIAIOSFODNN7EXAMPLE")
    assert ":MPLE]" in scrubbed


def test_clean_text_untouched() -> None:
    text = "the agent listed 3 files and wrote a summary"
    scrubbed, fired = redact(text)
    assert scrubbed == text
    assert fired == []


def test_truncation_after_redaction() -> None:
    secret = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    text = ("x" * 100) + secret + ("y" * 10_000)
    body, fired, truncated = redact_and_truncate(text, max_bytes=200)
    assert truncated
    assert len(body) == 200
    assert b"ghp_" not in body
    assert "github-token" in fired


def test_multiple_secrets_all_fired() -> None:
    text = (
        "AKIAIOSFODNN7EXAMPLE and xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
    )
    scrubbed, fired = redact(text)
    assert "AKIA" not in scrubbed
    assert "xoxb-" not in scrubbed
    assert fired == ["aws-access-key-id", "slack-token"]
