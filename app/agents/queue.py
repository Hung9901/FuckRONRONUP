import asyncio

class TaskQueue:
    def __init__(self):
        self.queue = asyncio.Queue(maxsize=100000)

    async def enqueue(self, item):
        await self.queue.put(item)

    async def dequeue(self):
        return await self.queue.get()
