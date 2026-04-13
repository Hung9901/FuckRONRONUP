from fastapi import FastAPI
from app.api.routes import router
from app.api.websocket import ws_router

app = FastAPI()

app.include_router(router)
app.include_router(ws_router)
