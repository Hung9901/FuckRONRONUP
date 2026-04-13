import asyncio
from collections import defaultdict
from app.core.config import settings


class RiskAggregator:
    """
    Thread-safe risk score accumulator with per-device locking.

    Using a per-device asyncio.Lock instead of a single global lock
    eliminates contention between independent devices — only concurrent
    updates *for the same device* need to wait on each other.
    """

    def __init__(self):
        self._scores: dict[str, int] = {}
        self._signals: dict[str, set[str]] = {}
        self._agent_hits: dict[str, dict[str, int]] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def _lock_for(self, device_id: str) -> asyncio.Lock:
        return self._locks[device_id]

    async def update(self, device_id: str, agent_result: dict) -> dict:
        async with self._lock_for(device_id):
            self._scores[device_id] = (
                self._scores.get(device_id, 0) + agent_result.get("risk_score", 0)
            )
            for flag in agent_result.get("flags", []):
                self._signals.setdefault(device_id, set()).add(flag)

            agent = agent_result.get("agent", "unknown")
            hits = self._agent_hits.setdefault(device_id, {})
            hits[agent] = hits.get(agent, 0) + 1

            return self._snapshot(device_id)

    def get(self, device_id: str) -> dict:
        return self._snapshot(device_id)

    def reset(self, device_id: str) -> None:
        self._scores.pop(device_id, None)
        self._signals.pop(device_id, None)
        self._agent_hits.pop(device_id, None)
        # Remove the lock too so it gets re-created clean next time
        self._locks.pop(device_id, None)

    def _snapshot(self, device_id: str) -> dict:
        total = self._scores.get(device_id, 0)
        signals = list(self._signals.get(device_id, set()))
        agent_hits = dict(self._agent_hits.get(device_id, {}))
        return {
            "device_id": device_id,
            "total_risk": total,
            "threat_level": self._level(total),
            "active_signals": signals,
            "agent_hits": agent_hits,
        }

    def _level(self, score: int) -> str:
        if score > settings.RISK_CRITICAL:
            return "CRITICAL"
        elif score > settings.RISK_HIGH:
            return "HIGH"
        elif score > settings.RISK_MEDIUM:
            return "MEDIUM"
        return "LOW"
