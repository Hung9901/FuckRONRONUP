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
    title="FuckRONRONUP Threat Detection",
    description="Real-time mobile threat detection pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

_static = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_static), name="static")

app.include_router(router)
app.include_router(ws_router)


@app.get("/")
async def dashboard():
    return FileResponse(_static / "index.html")
