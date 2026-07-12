"""Environment configuration with dev defaults matching infra/docker-compose.dev.yml."""

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    pg_dsn: str = field(
        default_factory=lambda: _env(
            "ABX_PG_DSN", "postgresql://abx:abx_dev_password@localhost:5432/abx"
        )
    )
    ch_host: str = field(default_factory=lambda: _env("ABX_CH_HOST", "localhost"))
    ch_port: int = field(default_factory=lambda: int(_env("ABX_CH_PORT", "8123")))
    ch_database: str = field(default_factory=lambda: _env("ABX_CH_DATABASE", "abx"))
    ch_user: str = field(default_factory=lambda: _env("ABX_CH_USER", "abx_app"))
    ch_password: str = field(
        default_factory=lambda: _env("ABX_CH_PASSWORD", "abx_app_dev_password")
    )
    s3_endpoint: str = field(
        default_factory=lambda: _env("ABX_S3_ENDPOINT", "http://localhost:9402")
    )
    s3_access_key: str = field(default_factory=lambda: _env("ABX_S3_ACCESS_KEY", "abx"))
    s3_secret_key: str = field(
        default_factory=lambda: _env("ABX_S3_SECRET_KEY", "abx_dev_password")
    )
    payload_bucket: str = field(default_factory=lambda: _env("ABX_PAYLOAD_BUCKET", "abx-payloads"))
    anchor_bucket: str = field(default_factory=lambda: _env("ABX_ANCHOR_BUCKET", "abx-anchors"))
    # ponytail: single shared admin key for read endpoints until dashboard auth
    # lands (Phase 4+); per-tenant read tokens replace this.
    admin_key: str = field(default_factory=lambda: _env("ABX_ADMIN_KEY", "dev-admin-key"))
    # Per-payload size cap after redaction, before digest (bytes).
    payload_max_bytes: int = field(
        default_factory=lambda: int(_env("ABX_PAYLOAD_MAX_BYTES", str(32 * 1024)))
    )
    max_batch_events: int = field(default_factory=lambda: int(_env("ABX_MAX_BATCH", "5000")))
    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            _env("ABX_CORS_ORIGINS", "http://localhost:3000").split(",")
        )
    )
    redis_url: str = field(default_factory=lambda: _env("ABX_REDIS_URL", "redis://localhost:6379"))
    web_url: str = field(default_factory=lambda: _env("ABX_WEB_URL", "http://localhost:3000"))
    github_app_slug: str = field(default_factory=lambda: _env("ABX_GITHUB_APP_SLUG", ""))
    github_app_id: str = field(default_factory=lambda: _env("ABX_GITHUB_APP_ID", ""))
    github_private_key: str = field(
        default_factory=lambda: _env("ABX_GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")
    )
    github_state_secret: str = field(
        default_factory=lambda: _env("ABX_GITHUB_STATE_SECRET", "dev-github-state-secret")
    )
    alert_cooldown_minutes: int = field(
        default_factory=lambda: int(_env("ABX_ALERT_COOLDOWN_MINUTES", "60"))
    )
    slack_webhook_url: str = field(
        default_factory=lambda: _env("ABX_SLACK_WEBHOOK_URL", "")
    )
    resend_api_key: str = field(default_factory=lambda: _env("ABX_RESEND_API_KEY", ""))
    alert_email_from: str = field(
        default_factory=lambda: _env("ABX_ALERT_EMAIL_FROM", "AgentBlackBox <alerts@example.com>")
    )
    aws_revoke_access_key_id: str = field(
        default_factory=lambda: _env("ABX_AWS_REVOKE_ACCESS_KEY_ID", "")
    )
    aws_revoke_secret_access_key: str = field(
        default_factory=lambda: _env("ABX_AWS_REVOKE_SECRET_ACCESS_KEY", "")
    )
    aws_revoke_session_token: str = field(
        default_factory=lambda: _env("ABX_AWS_REVOKE_SESSION_TOKEN", "")
    )
    github_revoke_token: str = field(
        default_factory=lambda: _env("ABX_GITHUB_REVOKE_TOKEN", "")
    )


settings = Settings()
