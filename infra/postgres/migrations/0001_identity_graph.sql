-- Identity graph + tenancy + chain heads (blueprint 4.2).
-- Invariant: credentials store fingerprints only, never secret values.

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ingest_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    -- sha256 of the token; the token itself is shown once at creation and never stored
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    -- write-only: this token class can never read anything by construction
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    framework TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'unknown'
        CHECK (environment IN ('prod', 'staging', 'dev', 'unknown')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);

CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'github')),
    kind TEXT NOT NULL,          -- iam_user | iam_role | gh_user | gh_app
    external_id TEXT NOT NULL,   -- ARN, GitHub login/app slug
    human_owner TEXT,
    UNIQUE (tenant_id, provider, external_id)
);

CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'github')),
    kind TEXT NOT NULL,          -- access_key | fine_grained_pat | deploy_key | app_installation | oauth_grant
    -- Fingerprint only: AWS AccessKeyId, GitHub PAT id, deploy key id. NEVER a secret value.
    fingerprint TEXT NOT NULL,
    owner_principal UUID REFERENCES principals(id),
    created_at_provider TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'revoked')),
    first_scanned TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_scanned TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, provider, fingerprint)
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    credential_id UUID REFERENCES credentials(id),
    principal_id UUID REFERENCES principals(id),
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'github')),
    scope TEXT NOT NULL,         -- policy ARN, PAT permission key, deploy key rw
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (credential_id IS NOT NULL OR principal_id IS NOT NULL)
);

CREATE TABLE resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider TEXT NOT NULL,
    kind TEXT NOT NULL,          -- s3_bucket | repo | db | ...
    identifier TEXT NOT NULL,    -- normalized, e.g. aws:s3:bucket
    environment TEXT NOT NULL DEFAULT 'unknown'
        CHECK (environment IN ('prod', 'staging', 'dev', 'unknown')),
    UNIQUE (tenant_id, provider, identifier)
);

-- Edges
CREATE TABLE agent_holds_credential (
    agent_id UUID NOT NULL REFERENCES agents(id),
    credential_id UUID NOT NULL REFERENCES credentials(id),
    inferred_from TEXT NOT NULL DEFAULT 'scan',  -- scan | traffic | manual
    PRIMARY KEY (agent_id, credential_id)
);

CREATE TABLE permission_reaches_resource (
    permission_id UUID NOT NULL REFERENCES permissions(id),
    resource_id UUID NOT NULL REFERENCES resources(id),
    access TEXT NOT NULL DEFAULT 'read' CHECK (access IN ('read', 'write', 'admin')),
    PRIMARY KEY (permission_id, resource_id)
);

-- Findings (blueprint 5.3)
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    finding_type TEXT NOT NULL CHECK (finding_type IN
        ('orphaned_credential', 'over_privileged', 'shadow_credential',
         'stale_authorization', 'blast_radius')),
    -- natural key for dedup across scan runs
    natural_key TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    credential_id UUID REFERENCES credentials(id),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, natural_key)
);

-- Scan runs: the scanner is auditable by its own standard (blueprint 5.3)
CREATE TABLE scan_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    api_calls INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed'))
);

-- Hash-chain heads, checkpointed per tenant on every write batch (blueprint 4.1)
CREATE TABLE chain_heads (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    head_hash TEXT NOT NULL,
    head_seq BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_credentials_tenant ON credentials(tenant_id);
CREATE INDEX idx_findings_tenant_status ON findings(tenant_id, status);
CREATE INDEX idx_agents_tenant ON agents(tenant_id);
