-- Phase 18: extend the identity graph to Google Workspace and Slack.
-- Same shape as 0013 (gcp) and 0017 (azure); read-only scan identities stay
-- separate from revocation credentials.

ALTER TABLE principals DROP CONSTRAINT principals_provider_check;
ALTER TABLE principals
    ADD CONSTRAINT principals_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp', 'azure', 'workspace', 'slack'));

ALTER TABLE credentials DROP CONSTRAINT credentials_provider_check;
ALTER TABLE credentials
    ADD CONSTRAINT credentials_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp', 'azure', 'workspace', 'slack'));

ALTER TABLE permissions DROP CONSTRAINT permissions_provider_check;
ALTER TABLE permissions
    ADD CONSTRAINT permissions_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp', 'azure', 'workspace', 'slack'));

ALTER TABLE integration_connections
    DROP CONSTRAINT integration_connections_provider_check;
ALTER TABLE integration_connections
    ADD CONSTRAINT integration_connections_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp', 'azure', 'workspace', 'slack'));

ALTER TABLE revocation_actions DROP CONSTRAINT revocation_actions_provider_check;
ALTER TABLE revocation_actions
    ADD CONSTRAINT revocation_actions_provider_check
    CHECK (provider IN ('aws', 'github', 'gcp', 'azure', 'workspace', 'slack'));
