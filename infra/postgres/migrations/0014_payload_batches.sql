-- Batch-packed payload objects.
--
-- Ingest previously wrote one object per payload event, which profiling showed
-- to be ~94% of ingest time and the throughput ceiling. Payloads in a single
-- ingest request now share one immutable object.
--
-- Because many payloads share an object, individual bytes cannot be removed.
-- Per-payload erasure is preserved by giving every payload its own data key:
-- deleting the segment row destroys the only key for that payload, which is a
-- single atomic delete rather than a read-modify-write against object storage.
-- Age-based retention later deletes the whole object, physically removing the
-- bytes.
--
-- payload_ref keeps its existing '{tenant_id}/{event_id}' form on purpose: it
-- is part of HASHED_FIELDS, so changing it would change event hashes and split
-- verification across old and new data. It becomes a logical identifier that
-- resolves through this table; events written before this migration have no
-- row here and fall back to being read as a direct object key.

-- Both tables cascade from tenants, unlike the primary records elsewhere in
-- the schema. This is derived storage holding per-payload data keys, and those
-- keys must never outlive the tenant they belong to: removing the tenant has
-- to remove the ability to read their payloads, not merely orphan it.
CREATE TABLE payload_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL UNIQUE,
    byte_size BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Retention sweeps by age per tenant, so order the index that way.
CREATE INDEX idx_payload_batches_tenant_created ON payload_batches (tenant_id, created_at);

CREATE TABLE payload_segments (
    -- '{tenant_id}/{event_id}', identical to the value stored on the event.
    payload_ref TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    batch_id UUID NOT NULL REFERENCES payload_batches(id) ON DELETE CASCADE,
    byte_offset BIGINT NOT NULL,
    byte_length INTEGER NOT NULL,
    -- Per-payload data key, wrapped with the configured master key. Deleting
    -- this row is the erasure operation.
    wrapped_key BYTEA NOT NULL,
    key_nonce BYTEA NOT NULL,
    data_nonce BYTEA NOT NULL
);

CREATE INDEX idx_payload_segments_tenant ON payload_segments (tenant_id);
CREATE INDEX idx_payload_segments_batch ON payload_segments (batch_id);
