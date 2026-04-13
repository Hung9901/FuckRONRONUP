from contextlib import asynccontextmanager
from fastapi import FastAPI
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

app.include_router(router)
app.include_router(ws_router)
