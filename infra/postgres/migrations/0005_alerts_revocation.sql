-- Explainable anomaly alerts, non-secret delivery configuration, and revoke audit.

CREATE TABLE alert_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    kind TEXT NOT NULL CHECK (kind IN ('slack', 'email')),
    target TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, target)
);

CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    rule_id TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    credential_ref TEXT,
    event_id UUID NOT NULL,
    session_id TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    hit_count INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_dispatched_at TIMESTAMPTZ,
    dispatch_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, dedupe_key)
);

CREATE TABLE revocation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    credential_id UUID NOT NULL REFERENCES credentials(id),
    action TEXT NOT NULL CHECK (action IN ('deactivate', 'delete', 'revoke')),
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'github')),
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_tenant_seen ON alerts(tenant_id, last_seen DESC);
CREATE INDEX idx_revocation_actions_tenant ON revocation_actions(tenant_id, created_at DESC);
