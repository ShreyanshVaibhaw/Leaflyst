-- Canonical event log. Append-only by construction:
-- the application user (abx_app, created below) has INSERT + SELECT only.
-- Blueprint 4.1: ORDER BY (tenant_id, session_id, seq), monthly partitions.

CREATE TABLE IF NOT EXISTS abx.events
(
    event_id          UUID,
    tenant_id         UUID,
    agent_id          String,
    session_id        String,
    seq               UInt64,
    ts                DateTime64(3, 'UTC'),
    source            LowCardinality(String),
    event_type        LowCardinality(String),
    op_name           String,
    op_provider       String DEFAULT '',
    op_target         String DEFAULT '',
    op_outcome        LowCardinality(String),
    op_duration_ms    Nullable(UInt64),
    credential_ref    String DEFAULT '',
    resource_refs     Array(String),
    payload_digest    FixedString(64),
    payload_ref       String DEFAULT '',
    payload_truncated Bool,
    redactions        Array(String),
    prev_hash         FixedString(64),
    event_hash        FixedString(64),
    ingested_at       DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, session_id, seq);

-- Application user: INSERT and SELECT only. No ALTER, no UPDATE/DELETE
-- (ClickHouse mutations are ALTER TABLE ... UPDATE/DELETE, so denying ALTER
-- denies mutation). This is the append-only guarantee at the grant level.
CREATE USER IF NOT EXISTS abx_app IDENTIFIED WITH sha256_password BY 'abx_app_dev_password';
GRANT INSERT, SELECT ON abx.events TO abx_app;
