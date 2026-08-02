-- Phase 23: roles and per-tenant scoped read tokens.
--
-- Replaces the single shared admin key that has guarded every read endpoint
-- since Phase 4. That key carries no tenant binding, so a caller holding it
-- supplies whatever tenant_id it likes; a scoped token binds its tenant, which
-- makes cross-tenant reads impossible by construction rather than by care.

-- Existing members were all effectively owners.
ALTER TABLE tenant_members
    ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';

ALTER TABLE tenant_members
    ADD CONSTRAINT tenant_members_role_check
    CHECK (role IN ('viewer', 'responder', 'admin', 'auditor'));

-- Deprovisioning marks rather than deletes: an operator who acted must stay
-- resolvable in the audit trail after they lose access.
ALTER TABLE tenant_members
    ADD COLUMN deactivated_at TIMESTAMPTZ;

CREATE TABLE read_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- sha256 only; the token is shown once at creation, exactly like
    -- ingest_tokens. Read tokens can never write or ingest.
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT read_tokens_role_check
        CHECK (role IN ('viewer', 'responder', 'admin', 'auditor'))
);

CREATE INDEX read_tokens_tenant_idx ON read_tokens (tenant_id);
