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
        self.workers = [
            Worker(self.queue, self.orchestrator, self.aggregator)
            for _ in range(100)
        ]
        for w in self.workers:
            asyncio.create_task(w.run())

    async def register(self, ws) -> int:
        agent_id = id(ws)
        self.agents[agent_id] = ws
        return agent_id

    async def unregister(self, agent_id: int):
        self.agents.pop(agent_id, None)

    async def dispatch(self, agent_id: int, event: dict):
        await self.queue.enqueue((str(agent_id), event))

    def risk(self, agent_id: int) -> dict:
        return self.aggregator.get(str(agent_id))
