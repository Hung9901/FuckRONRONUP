import asyncio


class RiskAggregator:
    def __init__(self):
        self._scores: dict[str, int] = {}
        self._signals: dict[str, set[str]] = {}
        self._lock = asyncio.Lock()

    async def update(self, device_id: str, agent_result: dict) -> dict:
        async with self._lock:
            self._scores[device_id] = (
                self._scores.get(device_id, 0) + agent_result.get("risk_score", 0)
            )
            # Collect signal flags emitted by the agent
            for flag in agent_result.get("flags", []):
                self._signals.setdefault(device_id, set()).add(flag)

            total = self._scores[device_id]
            signals = list(self._signals.get(device_id, set()))

        return {
            "device_id": device_id,
            "total_risk": total,
            "threat_level": self._level(total),
            "active_signals": signals,
        }

    def get(self, device_id: str) -> dict:
        total = self._scores.get(device_id, 0)
        signals = list(self._signals.get(device_id, set()))
        return {
            "device_id": device_id,
            "total_risk": total,
            "threat_level": self._level(total),
            "active_signals": signals,
        }

    def reset(self, device_id: str) -> None:
        self._scores.pop(device_id, None)
        self._signals.pop(device_id, None)

    @staticmethod
    def _level(score: int) -> str:
        if score > 20:
            return "CRITICAL"
        elif score > 10:
            return "HIGH"
        elif score > 5:
            return "MEDIUM"
        return "LOW"
