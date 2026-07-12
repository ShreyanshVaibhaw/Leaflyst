-- Self-serve identity-to-tenant mapping. Provider user references are opaque IDs.

CREATE TABLE tenant_members (
    user_ref TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenant_members_tenant ON tenant_members(tenant_id);

CREATE TABLE scan_upload_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE demo_tenants (
    owner_tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    demo_tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
