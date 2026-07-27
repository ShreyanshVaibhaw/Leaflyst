-- Phase 12: extend the identity graph to Google Cloud without weakening the
-- separation between read-only scan identities and revocation credentials.

ALTER TABLE principals DROP CONSTRAINT principals_provider_check;
ALTER TABLE principals
    ADD CONSTRAINT principals_provider_check CHECK (provider IN ('aws', 'github', 'gcp'));

ALTER TABLE credentials DROP CONSTRAINT credentials_provider_check;
ALTER TABLE credentials
    ADD CONSTRAINT credentials_provider_check CHECK (provider IN ('aws', 'github', 'gcp'));

ALTER TABLE permissions DROP CONSTRAINT permissions_provider_check;
ALTER TABLE permissions
    ADD CONSTRAINT permissions_provider_check CHECK (provider IN ('aws', 'github', 'gcp'));

ALTER TABLE integration_connections
    DROP CONSTRAINT integration_connections_provider_check;
ALTER TABLE integration_connections
    ADD CONSTRAINT integration_connections_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp'));

ALTER TABLE revocation_actions DROP CONSTRAINT revocation_actions_provider_check;
ALTER TABLE revocation_actions
    ADD CONSTRAINT revocation_actions_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp'));
