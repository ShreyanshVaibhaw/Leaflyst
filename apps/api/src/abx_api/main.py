from fastapi import FastAPI

from abx_api.ingest import router as ingest_router
from abx_api.verify import router as verify_router

app = FastAPI(title="AgentBlackBox API", version="0.1.0")
app.include_router(ingest_router)
app.include_router(verify_router)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
