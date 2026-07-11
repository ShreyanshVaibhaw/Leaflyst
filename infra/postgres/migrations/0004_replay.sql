-- Replay sequence allocation and tenant-scoped, read-only session shares.

CREATE TABLE session_sequences (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    session_id TEXT NOT NULL,
    next_seq BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, session_id)
);

CREATE TABLE session_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    session_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_session_shares_tenant_session
    ON session_shares(tenant_id, session_id);
