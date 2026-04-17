import asyncio
import time
from collections.abc import AsyncIterable
from app.agents.orchestrator import Orchestrator
from app.services.risk_aggregator import RiskAggregator
from app.utils import metrics


class StreamProcessor:
    """
    Processes an async stream of (device_id, event) pairs through the
    agent pipeline, updating the shared RiskAggregator for each event
    and yielding risk snapshots.

    Usage:
        async for snapshot in processor.process(stream):
            ...  # snapshot is the latest risk dict for the device
    """

    def __init__(self, orchestrator: Orchestrator, aggregator: RiskAggregator):
        self.orchestrator = orchestrator
        self.aggregator = aggregator

    async def process(
        self,
        stream: AsyncIterable[tuple[str, dict]],
    ):
        """Yield a risk snapshot after each event is processed."""
        async for device_id, event in stream:
            snapshot = await self._handle(device_id, event)
            if snapshot is not None:
                yield snapshot

    async def process_batch(
        self,
        device_id: str,
        events: list[dict],
    ) -> list[dict]:
        """Process a list of events for one device, returning all snapshots."""
        results = []
        for event in events:
            snapshot = await self._handle(device_id, event)
            if snapshot is not None:
                results.append(snapshot)
        return results

    async def _handle(self, device_id: str, event: dict) -> dict | None:
        t0 = time.monotonic()
        try:
            agent_results = await self.orchestrator.route(event)
            metrics.events_processed.inc()
            metrics.processing_latency.observe(time.monotonic() - t0)
            snapshot = {}
            for result in agent_results:
                snapshot = await self.aggregator.update(device_id, result)
            return snapshot or self.aggregator.get(device_id)
        except Exception:
            metrics.agent_errors.inc()
            return None
