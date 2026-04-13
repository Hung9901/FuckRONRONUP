import orjson

class IngestionAgent:
    """Deserializes and validates raw binary frames from the WebSocket layer."""

    def can_handle(self, event):
        return event.get("type") == "raw"

    async def process(self, event):
        try:
            payload = orjson.loads(event["data"])
            return {"agent": "ingestion", "parsed": payload, "risk_score": 0}
        except Exception as exc:
            return {
                "agent": "ingestion",
                "error": str(exc),
                "risk_score": 1,
            }
