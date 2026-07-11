-- Usage metering (blueprint 9.2): count events per tenant per day so pricing
-- can be turned on later without re-instrumenting.

CREATE TABLE metering_daily (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    day DATE NOT NULL,
    events BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);
