-- Provider connections contain identifiers and status only. Provider secrets
-- remain in process environment / the deployment secret manager.

CREATE TABLE integration_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'github')),
    external_id TEXT NOT NULL,
    account_login TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'connected'
        CHECK (status IN ('connected', 'disconnected', 'error')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, external_id)
);

CREATE INDEX idx_integration_connections_tenant
    ON integration_connections(tenant_id, provider, status);
