import orjson
from fastapi import APIRouter, WebSocket
from app.agents.manager import AgentManager

ws_router = APIRouter()
manager = AgentManager()

@ws_router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    agent_id = await manager.register(ws)

    try:
        while True:
            raw = await ws.receive_bytes()
            event = orjson.loads(raw)
            await manager.dispatch(agent_id, event)

            # Live risk feedback after each event
            risk = manager.risk(agent_id)
            await ws.send_bytes(orjson.dumps(risk))
    except Exception:
        await manager.unregister(agent_id)
