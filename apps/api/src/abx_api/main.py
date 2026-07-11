from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from abx_api.dashboard import router as dashboard_router
from abx_api.ingest import router as ingest_router
from abx_api.integrations import router as integrations_router
from abx_api.settings import settings
from abx_api.verify import router as verify_router

app = FastAPI(title="AgentBlackBox API", version="0.1.0")
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


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
