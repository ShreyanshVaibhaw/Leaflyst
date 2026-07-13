-- Isolate full-fidelity payload allowances per write-only recording token so
-- one untrusted producer cannot degrade capture for every recorder in a tenant.

CREATE TABLE metering_token_daily (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_id UUID NOT NULL REFERENCES ingest_tokens(id),
    day DATE NOT NULL,
    captured_payload_events BIGINT NOT NULL DEFAULT 0
        CHECK (captured_payload_events >= 0),
    PRIMARY KEY (tenant_id, token_id, day)
);

CREATE INDEX idx_metering_token_daily_token
    ON metering_token_daily(token_id, day);
