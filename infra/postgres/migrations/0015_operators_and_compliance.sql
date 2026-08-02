-- EU AI Act Article 12: identification of the natural persons involved, and a
-- retention floor that cannot be lowered below the regulatory minimum.
--
-- The operator is bound to the INGEST TOKEN, never asserted in the event body.
-- A write-only recording token is held by an agent we do not trust to be
-- honest, so letting it name a human would make attribution forgeable. The
-- token is minted by an authenticated dashboard user; that user is the
-- operator of record for everything recorded with it. Same reasoning that
-- makes tenant_id come from the token rather than the body.

CREATE TABLE operators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The dashboard identity (Clerk user ref) this operator corresponds to.
    user_ref TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    -- sha256 of the lowercased email, never the address itself. Personal data
    -- follows the same discipline as secrets: store a fingerprint where a
    -- fingerprint suffices, so an erasure request never touches the chain.
    email_fingerprint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_ref)
);

CREATE INDEX operators_tenant_idx ON operators (tenant_id);

-- Nullable: tokens minted before this migration have no operator of record,
-- and the evidence pack must report them as explicitly unattributed rather
-- than silently attributing them to someone.
ALTER TABLE ingest_tokens
    ADD COLUMN operator_id UUID REFERENCES operators(id) ON DELETE SET NULL;

-- Article 12 requires at least six months of retention. compliance_mode makes
-- that floor enforceable; retention_floor_days records which floor applied, so
-- a later policy change cannot rewrite what the record claims was in force.
ALTER TABLE tenant_settings
    ADD COLUMN compliance_mode BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN retention_floor_days INTEGER NOT NULL DEFAULT 180;

ALTER TABLE tenant_settings
    ADD CONSTRAINT tenant_settings_retention_floor
    CHECK (NOT compliance_mode OR retention_days >= retention_floor_days);
