-- Tool definition history per (tenant, server, tool).
--
-- Rule 5 hashes the whole inventory, which can only say that SOMETHING
-- changed. A rug-pull finding has to name the tool and show the change, and
-- the trust window is what makes it severe: a tool approved, used across many
-- sessions for days, then silently redefined is the attack (OWASP ASI04).
--
-- definition_text is recorded agent-adjacent content and is therefore
-- untrusted by blueprint 6: never executed, evaluated, or interpreted, and
-- rendered escaped. It is stored verbatim because an incident responder needs
-- the actual before/after, not a hash of it.

CREATE TABLE tool_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Self-reported server identity; unverified by the protocol, so it is a
    -- grouping key only and never a security decision.
    server_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    definition_text TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Distinct sessions that observed this exact definition: how much trust
    -- the definition accumulated before any change.
    sessions_seen INTEGER NOT NULL DEFAULT 1,
    superseded_at TIMESTAMPTZ,
    UNIQUE (tenant_id, server_name, tool_name, definition_hash)
);

CREATE INDEX tool_definitions_lookup_idx
    ON tool_definitions (tenant_id, server_name, tool_name, first_seen);

-- Last time the inventory was observed on the wire per (tenant, server).
-- The 2026-07-28 spec added ttlMs/cacheScope so clients cache list results and
-- poll less, which lengthens the blind window between observations. Confidence
-- has to be reported from this, not assumed.
CREATE TABLE tool_inventory_observations (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    server_name TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    inventory_hash TEXT NOT NULL,
    ttl_ms BIGINT,
    cache_scope TEXT,
    PRIMARY KEY (tenant_id, server_name)
);
