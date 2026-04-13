import asyncio
import time
from app.agents.orchestrator import Orchestrator
from app.services.risk_aggregator import RiskAggregator
from app.core.logging import get_logger
from app.utils import metrics

log = get_logger(__name__)


class Worker:
    def __init__(self, queue, orchestrator: Orchestrator, aggregator: RiskAggregator):
        self.queue = queue
        self.orchestrator = orchestrator
        self.aggregator = aggregator
        self._running = True

    async def run(self):
        while self._running:
            try:
                task = await self.queue.dequeue()
                await self.process(task)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.exception("worker_error", extra={"error": str(exc)})
                # Brief backoff to avoid a hot error loop on persistent failures
                await asyncio.sleep(0.1)

    async def process(self, task):
        device_id, event = task
        t0 = time.monotonic()
        try:
            results = await self.orchestrator.route(event)
            for result in results:
                await self.aggregator.update(device_id, result)
            metrics.events_processed.inc()
            metrics.processing_latency.observe(time.monotonic() - t0)
        except Exception as exc:
            metrics.agent_errors.inc()
            log.error(
                "process_error",
                extra={"device_id": device_id, "event_type": event.get("type"), "error": str(exc)},
            )

    def stop(self):
        self._running = False
