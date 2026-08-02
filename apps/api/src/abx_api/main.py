from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from abx_api.alerts import router as alerts_router
from abx_api.body_limit import RequestBodyLimit
from abx_api.compliance import router as compliance_router
from abx_api.dashboard import router as dashboard_router
from abx_api.demo import router as demo_router
from abx_api.evidence import router as evidence_router
from abx_api.health import router as health_router
from abx_api.ingest import router as ingest_router
from abx_api.integrations import router as integrations_router
from abx_api.local_scan import router as local_scan_router
from abx_api.normalize import router as normalize_router
from abx_api.onboarding import router as onboarding_router
from abx_api.policy import router as policy_router
from abx_api.rate_limit import RateLimit
from abx_api.replay import router as replay_router
from abx_api.reports import router as reports_router
from abx_api.revocation import router as revocation_router
from abx_api.settings import production_config_errors, settings
from abx_api.tenant_settings import router as tenant_settings_router
from abx_api.verify import router as verify_router

app = FastAPI(title="Leaflyst API", version="0.1.0")
configuration_errors = production_config_errors(settings)
if configuration_errors:
    raise RuntimeError("unsafe production configuration: " + "; ".join(configuration_errors))
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
if settings.require_https:
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    RequestBodyLimit,
    limits={
        "/v1/ingest": settings.ingest_body_max_bytes,
        "/v1/otlp/traces": settings.otlp_body_max_bytes,
        "/v1/traces": settings.otlp_body_max_bytes,
        "/v1/scans/local": settings.scan_upload_max_bytes,
    },
)
app.add_middleware(RateLimit)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ingest_router)
app.include_router(verify_router)
app.include_router(dashboard_router)
app.include_router(integrations_router)
app.include_router(normalize_router)
app.include_router(replay_router)
app.include_router(alerts_router)
app.include_router(revocation_router)
app.include_router(reports_router)
app.include_router(demo_router)
app.include_router(local_scan_router)
app.include_router(onboarding_router)
app.include_router(evidence_router)
app.include_router(compliance_router)
app.include_router(policy_router)
app.include_router(tenant_settings_router)
app.include_router(health_router)
