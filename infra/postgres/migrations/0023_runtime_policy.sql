-- Phase 25: runtime policy, as a separate opt-in plane.
--
-- Policies are VERSIONED and every version is retained. A customer must be able
-- to prove which policy was in force at any past moment, which means an edit
-- writes a new version rather than overwriting the old one - the same reason
-- the event log is append-only.
--
-- Enforcement is off unless a tenant turns it on. The product's failure mode is
-- "agent keeps working, recording degrades"; a blocking plane inverts that, so
-- it cannot be something a customer discovers they had.

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    -- 'allow' means an outage of ours does not become an outage of theirs.
    -- 'deny' is opt-in per policy and never inherited from a default.
    on_error TEXT NOT NULL DEFAULT 'allow' CHECK (on_error IN ('allow', 'deny')),
    priority INTEGER NOT NULL DEFAULT 100,
    match_destructive BOOLEAN NOT NULL DEFAULT FALSE,
    match_operations TEXT[] NOT NULL DEFAULT '{}',
    match_tools TEXT[] NOT NULL DEFAULT '{}',
    match_resource_prefixes TEXT[] NOT NULL DEFAULT '{}',
    match_agents TEXT[] NOT NULL DEFAULT '{}',
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set when a newer version replaces this one. History is never deleted.
    superseded_at TIMESTAMPTZ,
    UNIQUE (tenant_id, policy_id, version)
);

CREATE INDEX policies_live_idx
    ON policies (tenant_id, priority) WHERE superseded_at IS NULL;

-- Enforcement is per tenant and defaults to off.
ALTER TABLE tenant_settings
    ADD COLUMN policy_enforcement BOOLEAN NOT NULL DEFAULT FALSE;
