from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.routes import router
from app.api.websocket import ws_router, manager
from app.core.logging import get_logger

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("startup")
    await manager.startup()
    yield
    log.info("shutdown")
    await manager.shutdown()


app = FastAPI(
    title="SENTINEL — Mobile Threat Detection Platform",
    description=(
        "Enterprise-grade real-time mobile threat detection pipeline. "
        "Combines multi-agent behavioral analysis, MITRE ATT&CK for Mobile "
        "technique mapping, attack-graph scoring, and Claude Opus 4.7 AI "
        "threat intelligence with webhook alerting."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

_static = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_static), name="static")

app.include_router(router)
app.include_router(ws_router)


@app.get("/")
async def dashboard():
    return FileResponse(_static / "index.html")


@app.get("/tutorial")
async def tutorial():
    return FileResponse(_static / "tutorial.html")
