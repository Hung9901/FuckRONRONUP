import redis.asyncio as aioredis
from typing import AsyncGenerator

class RedisStreamQueue:
    def __init__(self, url: str, stream: str = "events"):
        self.url = url
        self.stream = stream
        self.redis = None

    async def connect(self):
        self.redis = await aioredis.from_url(self.url)

    async def enqueue(self, data: dict):
        await self.redis.xadd(self.stream, data)

    async def consume(self) -> AsyncGenerator:
        last_id = "$"
        while True:
            messages = await self.redis.xread({self.stream: last_id}, block=1000)
            for _, entries in messages:
                for entry_id, fields in entries:
                    last_id = entry_id
                    yield fields
