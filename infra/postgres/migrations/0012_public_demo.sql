-- Anonymous PocketOS runs get isolated tenant state. Only a one-way visitor
-- reference is stored; the browser token and provider secret values never are.

CREATE TABLE public_demo_tenants (
    visitor_ref TEXT PRIMARY KEY
        CHECK (visitor_ref ~ '^[0-9a-f]{64}$'),
    demo_tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    runs_in_window INTEGER NOT NULL DEFAULT 0
        CHECK (runs_in_window >= 0),
    last_run_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_public_demo_tenants_expires
    ON public_demo_tenants(expires_at);
