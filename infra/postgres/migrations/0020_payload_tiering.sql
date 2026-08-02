-- Phase 22: age-based payload storage tiering.
--
-- Batch packing means many payloads share one object, so tiering moves the
-- OBJECT and leaves every payload_segments row untouched: byte offsets,
-- wrapped keys, and erasure semantics are unaffected by a storage-class
-- transition.
--
-- Only immediately-readable classes are ever used (see tiering.py). Archive
-- classes would make a retained payload unproducible without a restore, which
-- defeats the point of retaining it.

ALTER TABLE payload_batches
    ADD COLUMN tiered_at TIMESTAMPTZ,
    ADD COLUMN storage_class TEXT NOT NULL DEFAULT 'STANDARD';

-- The tiering job's working set: batches not yet transitioned, oldest first.
CREATE INDEX payload_batches_untiered_idx
    ON payload_batches (created_at) WHERE tiered_at IS NULL;

-- 0 disables tiering for a tenant, which is the default: moving storage class
-- is a cost decision a customer opts into, not something done to them.
ALTER TABLE tenant_settings
    ADD COLUMN payload_tier_days INTEGER NOT NULL DEFAULT 0;

ALTER TABLE tenant_settings
    ADD CONSTRAINT tenant_settings_tier_before_retention
    CHECK (payload_tier_days = 0 OR payload_tier_days < retention_days);
