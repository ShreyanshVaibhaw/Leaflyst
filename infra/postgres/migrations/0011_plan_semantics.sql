-- Keep aggregate plan reporting separate from the independently protected
-- per-token full-fidelity payload allowance.

ALTER TABLE tenant_plans
    ADD COLUMN per_token_daily_payload_limit BIGINT
        CHECK (per_token_daily_payload_limit IS NULL OR per_token_daily_payload_limit > 0);

UPDATE tenant_plans
SET per_token_daily_payload_limit = daily_event_limit
WHERE per_token_daily_payload_limit IS NULL;

ALTER TABLE ingest_tokens
    ADD CONSTRAINT ingest_tokens_tenant_id_id_unique UNIQUE (tenant_id, id);

ALTER TABLE metering_token_daily
    DROP CONSTRAINT metering_token_daily_token_id_fkey,
    ADD CONSTRAINT metering_token_daily_tenant_token_fkey
        FOREIGN KEY (tenant_id, token_id)
        REFERENCES ingest_tokens(tenant_id, id);
