from app.agents.orchestrator import Orchestrator
from app.services.risk_aggregator import RiskAggregator


class Worker:
    def __init__(self, queue, orchestrator: Orchestrator, aggregator: RiskAggregator):
        self.queue = queue
        self.orchestrator = orchestrator
        self.aggregator = aggregator

    async def run(self):
        while True:
            task = await self.queue.dequeue()
            await self.process(task)

    async def process(self, task):
        device_id, event = task
        results = await self.orchestrator.route(event)
        for result in results:
            await self.aggregator.update(device_id, result)
