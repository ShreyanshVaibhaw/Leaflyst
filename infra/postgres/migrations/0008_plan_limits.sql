-- Launch plan limits are deliberately independent of payment-provider state.
-- A NULL limit means unlimited recording. Configured limits degrade payload
-- capture to metadata-only; they never reject authenticated event batches.

CREATE TABLE tenant_plans (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    plan_key TEXT NOT NULL DEFAULT 'unlimited'
        CHECK (plan_key ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    daily_event_limit BIGINT CHECK (daily_event_limit IS NULL OR daily_event_limit > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
