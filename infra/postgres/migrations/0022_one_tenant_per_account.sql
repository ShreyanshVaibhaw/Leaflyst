-- A provider account may be connected to at most ONE tenant.
--
-- The previous uniqueness was (tenant_id, provider, external_id), which is
-- per-tenant and therefore let two tenants claim the same account at once.
-- That is only a bookkeeping oddity when each tenant supplies its own
-- credential, but the GCP scanner authenticates with a single deployment-wide
-- principal: once tenant A grants that principal access to project X, any
-- tenant that names project X gets A's findings written into its own graph.
-- Project ids are guessable, so this is a cross-tenant leak of exactly the
-- data the product exists to protect.
--
-- Scoping the constraint to live connections on purpose: a tenant that
-- disconnects must not permanently block another from connecting the same
-- account, which would turn this into a denial-of-service primitive.

CREATE UNIQUE INDEX integration_connections_account_once
    ON integration_connections (provider, external_id)
    WHERE status = 'connected';
