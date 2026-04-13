import asyncio
from app.agents.worker import Worker
from app.agents.queue import TaskQueue
from app.agents.orchestrator import Orchestrator
from app.agents.ingestion_agent import IngestionAgent
from app.agents.accessibility_agent import AccessibilityAgent
from app.agents.persistence_agent import PersistenceAgent
from app.agents.permission_agent import PermissionAgent
from app.agents.anomaly_agent import AnomalyAgent
from app.agents.exfil_agent import ExfilAgent
from app.agents.ui_agent import UIAgent
from app.agents.phishing_agent import PhishingAgent
from app.services.risk_aggregator import RiskAggregator
from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


class AgentManager:
    def __init__(self):
        self.agents: dict[int, object] = {}
        self.queue = TaskQueue()
        self.aggregator = RiskAggregator()
        self.orchestrator = Orchestrator([
            IngestionAgent(),
            PhishingAgent(),
            AccessibilityAgent(),
            PersistenceAgent(),
            PermissionAgent(),
            AnomalyAgent(),
            ExfilAgent(),
            UIAgent(),
        ])
        self._worker_tasks: list[asyncio.Task] = []
        self.workers = [
            Worker(self.queue, self.orchestrator, self.aggregator)
            for _ in range(settings.MAX_WORKERS)
        ]

    async def startup(self):
        log.info("agent_manager_start", extra={"workers": len(self.workers)})
        for w in self.workers:
            task = asyncio.create_task(w.run())
            self._worker_tasks.append(task)

    async def shutdown(self):
        log.info("agent_manager_shutdown")
        for w in self.workers:
            w.stop()
        for task in self._worker_tasks:
            task.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)

    async def register(self, ws) -> int:
        agent_id = id(ws)
        self.agents[agent_id] = ws
        log.info("agent_registered", extra={"agent_id": agent_id})
        return agent_id

    async def unregister(self, agent_id: int):
        self.agents.pop(agent_id, None)
        log.info("agent_unregistered", extra={"agent_id": agent_id})

    async def dispatch(self, agent_id: int, event: dict) -> bool:
        enqueued = await self.queue.enqueue((str(agent_id), event))
        if not enqueued:
            log.warning(
                "queue_full_drop",
                extra={"agent_id": agent_id, "event_type": event.get("type")},
            )
        return enqueued

    def risk(self, agent_id: int) -> dict:
        return self.aggregator.get(str(agent_id))

    def queue_size(self) -> int:
        return self.queue.size()
