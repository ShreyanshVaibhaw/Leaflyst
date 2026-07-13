from __future__ import annotations

from dataclasses import replace

from abx_api.settings import Settings, production_config_errors


def test_production_rejects_insecure_defaults() -> None:
    value = replace(Settings(), environment="production", anchor_retention_days=0)
    errors = production_config_errors(value)
    assert any("HTTPS" in error for error in errors)
    assert any("ADMIN_KEY" in error for error in errors)
    assert any("STATE_SECRET" in error for error in errors)
    assert any("ANCHOR_RETENTION" in error for error in errors)


def test_production_accepts_hardened_transport_and_secrets() -> None:
    value = replace(
        Settings(),
        environment="production",
        require_https=True,
        admin_key="a" * 32,
        github_state_secret="g" * 32,
        s3_server_side_encryption="AES256",
    )
    assert production_config_errors(value) == []
