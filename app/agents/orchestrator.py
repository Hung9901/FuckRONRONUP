import asyncio


class Orchestrator:
    def __init__(self, agents):
        self.agents = agents

    async def route(self, event: dict) -> list[dict]:
        """Dispatch event to all capable agents in parallel."""
        capable = [a for a in self.agents if a.can_handle(event)]
        if not capable:
            return []
        return list(await asyncio.gather(*[a.process(event) for a in capable]))


async def process_batch(orchestrator: "Orchestrator", events: list[dict]) -> list[list[dict]]:
    return list(await asyncio.gather(*[orchestrator.route(e) for e in events]))
