from __future__ import annotations

import base64
from dataclasses import replace

from abx_api.settings import Settings, production_config_errors

REAL_MASTER_KEY = base64.b64encode(b"k" * 32).decode()


def _hardened(**overrides: object) -> Settings:
    """A production config with every guarded secret set correctly."""
    base: dict[str, object] = {
        "environment": "production",
        "require_https": True,
        "admin_key": "a" * 32,
        "github_state_secret": "g" * 32,
        "s3_server_side_encryption": "AES256",
        "payload_master_key": REAL_MASTER_KEY,
    }
    base.update(overrides)
    return replace(Settings(), **base)  # type: ignore[arg-type]


def test_production_rejects_insecure_defaults() -> None:
    value = replace(Settings(), environment="production", anchor_retention_days=0)
    errors = production_config_errors(value)
    assert any("HTTPS" in error for error in errors)
    assert any("ADMIN_KEY" in error for error in errors)
    assert any("STATE_SECRET" in error for error in errors)
    assert any("ANCHOR_RETENTION" in error for error in errors)


def test_production_accepts_hardened_transport_and_secrets() -> None:
    assert production_config_errors(_hardened()) == []


def test_production_rejects_the_committed_dev_payload_key() -> None:
    """The dev key is public in the repository; using it would make payload
    encryption - and therefore erasure by key deletion - meaningless."""
    value = replace(_hardened(), payload_master_key=Settings().payload_master_key)
    errors = production_config_errors(value)
    assert any("PAYLOAD_MASTER_KEY" in error for error in errors)


def test_production_rejects_malformed_payload_key() -> None:
    errors = production_config_errors(_hardened(payload_master_key="not base64 !!"))
    assert any("PAYLOAD_MASTER_KEY" in error for error in errors)


def test_production_rejects_wrong_length_payload_key() -> None:
    short = base64.b64encode(b"tooshort").decode()
    errors = production_config_errors(_hardened(payload_master_key=short))
    assert any("32 bytes" in error for error in errors)


def test_public_demo_limits_are_validated_in_production() -> None:
    value = replace(
        Settings(),
        environment="production",
        require_https=True,
        admin_key="a" * 32,
        github_state_secret="g" * 32,
        s3_server_side_encryption="AES256",
        demo_enabled=True,
        public_demo_max_runs_per_hour=0,
        public_demo_ttl_hours=0,
    )
    errors = production_config_errors(value)
    assert "ABX_PUBLIC_DEMO_MAX_RUNS_PER_HOUR must be at least 1" in errors
    assert "ABX_PUBLIC_DEMO_TTL_HOURS must be between 1 and 720" in errors
