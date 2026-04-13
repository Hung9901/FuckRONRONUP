import orjson
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.agents.manager import AgentManager
from app.core.logging import get_logger
from app.utils import metrics

ws_router = APIRouter()
manager = AgentManager()
log = get_logger(__name__)


@ws_router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    agent_id = await manager.register(ws)
    log.info("ws_connected", extra={"agent_id": agent_id})

    try:
        while True:
            raw = await ws.receive_bytes()
            try:
                event = orjson.loads(raw)
            except Exception as exc:
                await ws.send_bytes(orjson.dumps({"error": "invalid_json", "detail": str(exc)}))
                continue

            metrics.messages_received.inc()
            enqueued = await manager.dispatch(agent_id, event)
            if not enqueued:
                metrics.events_dropped.inc()
                await ws.send_bytes(orjson.dumps({"error": "queue_full"}))
                continue

            risk = manager.risk(agent_id)
            await ws.send_bytes(orjson.dumps(risk))

    except WebSocketDisconnect:
        log.info("ws_disconnected", extra={"agent_id": agent_id})
    except Exception as exc:
        log.error("ws_error", extra={"agent_id": agent_id, "error": str(exc)})
    finally:
        await manager.unregister(agent_id)
