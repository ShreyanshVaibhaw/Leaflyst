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


settings = Settings()
