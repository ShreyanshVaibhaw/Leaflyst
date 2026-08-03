"""Environment configuration with dev defaults matching infra/docker-compose.dev.yml."""

import base64
import os
from dataclasses import dataclass, field

# Committed dev-only key for the local stack. Production must override it;
# production_config_errors rejects this exact value.
DEV_PAYLOAD_MASTER_KEY = "ZGV2LW9ubHktcGF5bG9hZC1tYXN0ZXIta2V5LTMyYnk="


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    environment: str = field(default_factory=lambda: _env("ABX_ENV", "development"))
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
    anchor_retention_days: int = field(
        default_factory=lambda: int(_env("ABX_ANCHOR_RETENTION_DAYS", "3650"))
    )
    s3_server_side_encryption: str = field(
        default_factory=lambda: _env("ABX_S3_SERVER_SIDE_ENCRYPTION", "")
    )
    require_https: bool = field(
        default_factory=lambda: _env("ABX_REQUIRE_HTTPS", "false").lower() == "true"
    )
    allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            _env("ABX_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
        )
    )
    # ponytail: single shared admin key for read endpoints until dashboard auth
    # lands (Phase 4+); per-tenant read tokens replace this.
    admin_key: str = field(default_factory=lambda: _env("ABX_ADMIN_KEY", "dev-admin-key"))
    # Per-payload size cap after redaction, before digest (bytes).
    payload_max_bytes: int = field(
        default_factory=lambda: int(_env("ABX_PAYLOAD_MAX_BYTES", str(32 * 1024)))
    )
    # Wraps the per-payload data keys that make erasure a single row delete.
    # Base64-encoded 32 bytes. The default is DEV ONLY and is rejected in
    # production by production_config_errors; losing the real key makes every
    # stored payload permanently unreadable.
    payload_master_key: str = field(
        default_factory=lambda: _env("ABX_PAYLOAD_MASTER_KEY", DEV_PAYLOAD_MASTER_KEY)
    )
    # Comma-separated 'id:base64' keys kept for READS only, so payloads written
    # before a rotation stay readable until the re-wrap job has moved them.
    # Removing a key here while segments still reference it fails startup.
    payload_retired_keys: str = field(
        default_factory=lambda: _env("ABX_PAYLOAD_RETIRED_KEYS", "")
    )
    # Cold class for aged payload batches. Must remain immediately readable:
    # an archive class would make a retained payload unproducible without a
    # restore, which an incident responder or auditor cannot wait for.
    payload_cold_storage_class: str = field(
        default_factory=lambda: _env("ABX_PAYLOAD_COLD_STORAGE_CLASS", "STANDARD_IA")
    )
    max_batch_events: int = field(default_factory=lambda: int(_env("ABX_MAX_BATCH", "5000")))
    scan_upload_max_bytes: int = field(
        default_factory=lambda: int(_env("ABX_SCAN_UPLOAD_MAX_BYTES", str(2 * 1024 * 1024)))
    )
    ingest_body_max_bytes: int = field(
        default_factory=lambda: int(_env("ABX_INGEST_BODY_MAX_BYTES", str(64 * 1024 * 1024)))
    )
    otlp_body_max_bytes: int = field(
        default_factory=lambda: int(_env("ABX_OTLP_BODY_MAX_BYTES", str(16 * 1024 * 1024)))
    )
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
        default_factory=lambda: _env("ABX_ALERT_EMAIL_FROM", "Leaflyst <alerts@example.com>")
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
    gcp_scanner_principal: str = field(
        default_factory=lambda: _env("ABX_GCP_SCANNER_PRINCIPAL", "")
    )
    demo_enabled: bool = field(
        default_factory=lambda: _env("ABX_DEMO_ENABLED", "false").lower() == "true"
    )
    public_demo_max_runs_per_hour: int = field(
        default_factory=lambda: int(_env("ABX_PUBLIC_DEMO_MAX_RUNS_PER_HOUR", "5"))
    )
    public_demo_ttl_hours: int = field(
        default_factory=lambda: int(_env("ABX_PUBLIC_DEMO_TTL_HOURS", "24"))
    )
    # The per-visitor demo limit is keyed on a value the visitor chooses, so it
    # bounds one polite visitor and nothing else. These bound the whole feature.
    public_demo_max_runs_per_hour_global: int = field(
        default_factory=lambda: int(_env("ABX_PUBLIC_DEMO_GLOBAL_RUNS_PER_HOUR", "200"))
    )
    public_demo_max_live_tenants: int = field(
        default_factory=lambda: int(_env("ABX_PUBLIC_DEMO_MAX_LIVE_TENANTS", "500"))
    )
    # How many reverse proxies sit in front of this process. Zero means the peer
    # address IS the client and X-Forwarded-For is ignored outright, which is the
    # only safe default: a forwarded header from an untrusted peer is just a
    # request body with a header's name.
    trusted_proxy_hops: int = field(
        default_factory=lambda: int(_env("ABX_TRUSTED_PROXY_HOPS", "0"))
    )
    rate_limit_enabled: bool = field(
        default_factory=lambda: _env("ABX_RATE_LIMIT_ENABLED", "true").lower() == "true"
    )
    rate_limit_window_seconds: int = field(
        default_factory=lambda: int(_env("ABX_RATE_LIMIT_WINDOW_SECONDS", "60"))
    )
    # Per caller (token if presented, otherwise client address).
    rate_limit_requests: int = field(
        default_factory=lambda: int(_env("ABX_RATE_LIMIT_REQUESTS", "600"))
    )
    # Per caller, for routes that fan out into object storage, PDF rendering, or
    # a full-chain read. One caller can exhaust the process with very few of these.
    rate_limit_costly_requests: int = field(
        default_factory=lambda: int(_env("ABX_RATE_LIMIT_COSTLY_REQUESTS", "30"))
    )
    # Across every caller, so a distributed flood still meets a ceiling.
    rate_limit_global_requests: int = field(
        default_factory=lambda: int(_env("ABX_RATE_LIMIT_GLOBAL_REQUESTS", "6000"))
    )


settings = Settings()


def _keyring_errors(value: Settings) -> list[str]:
    """Validate every configured payload master key.

    Kept here rather than in payload_crypto so a bad key is a startup config
    error alongside the others, not an import-time explosion.
    """
    errors: list[str] = []
    entries = [("ABX_PAYLOAD_MASTER_KEY", value.payload_master_key, True)]
    entries += [
        ("ABX_PAYLOAD_RETIRED_KEYS", entry, False)
        for entry in value.payload_retired_keys.split(",")
        if entry.strip()
    ]
    seen: set[str] = set()
    for name, raw, active in entries:
        spec = raw.strip()
        if ":" in spec:
            key_id, _, encoded = spec.partition(":")
        elif active:
            key_id, encoded = "k1", spec
        else:
            errors.append(f"{name} entries must be 'id:base64'")
            continue
        key_id = key_id.strip()
        if key_id in seen:
            errors.append(f"payload master key id '{key_id}' is configured twice")
        seen.add(key_id)
        try:
            if len(base64.b64decode(encoded.strip(), validate=True)) != 32:
                errors.append(f"{name} key '{key_id}' must decode to 32 bytes")
        except Exception:
            errors.append(f"{name} key '{key_id}' must be valid base64")
    return errors


def production_config_errors(value: Settings) -> list[str]:
    """Reject unsafe production defaults before serving requests."""
    if value.environment != "production":
        return []
    errors: list[str] = []
    if not value.require_https:
        errors.append("ABX_REQUIRE_HTTPS must be true")
    if value.admin_key == "dev-admin-key" or len(value.admin_key) < 32:
        errors.append("ABX_ADMIN_KEY must be a strong non-default value")
    if (
        value.github_state_secret == "dev-github-state-secret"  # noqa: S105 - rejects it
        or len(value.github_state_secret) < 32
    ):
        errors.append("ABX_GITHUB_STATE_SECRET must be a strong non-default value")
    if not value.s3_server_side_encryption:
        errors.append("ABX_S3_SERVER_SIDE_ENCRYPTION must be configured")
    # The dev default is committed to the repository. Shipping with it would
    # encrypt every payload under a publicly known key, which also makes
    # erasure-by-key-deletion meaningless.
    if value.payload_master_key.split(":")[-1] == DEV_PAYLOAD_MASTER_KEY:
        errors.append("ABX_PAYLOAD_MASTER_KEY must be set to a generated value")
    # Every key in the keyring is validated, not just the active one: a
    # malformed retired key is silently fatal, because it only surfaces when
    # something tries to read a payload that key wrapped.
    errors.extend(_keyring_errors(value))
    if value.anchor_retention_days < 1:
        errors.append("ABX_ANCHOR_RETENTION_DAYS must be at least 1")
    if value.demo_enabled and value.public_demo_max_runs_per_hour < 1:
        errors.append("ABX_PUBLIC_DEMO_MAX_RUNS_PER_HOUR must be at least 1")
    if value.demo_enabled and not 1 <= value.public_demo_ttl_hours <= 24 * 30:
        errors.append("ABX_PUBLIC_DEMO_TTL_HOURS must be between 1 and 720")
    return errors
