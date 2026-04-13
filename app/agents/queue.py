import asyncio
from app.core.config import settings


class TaskQueue:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=settings.QUEUE_MAXSIZE)

    async def enqueue(self, item, timeout: float | None = None) -> bool:
        """
        Add an item to the queue.

        Args:
            item:    The item to enqueue.
            timeout: Max seconds to wait if the queue is full.
                     Defaults to settings.QUEUE_ENQUEUE_TIMEOUT.
                     Pass 0 for a non-blocking put (raises QueueFull immediately).

        Returns:
            True on success, False if the queue is full and the timeout expired.
        """
        if timeout is None:
            timeout = settings.QUEUE_ENQUEUE_TIMEOUT
        try:
            await asyncio.wait_for(self.queue.put(item), timeout=timeout)
            return True
        except (asyncio.TimeoutError, asyncio.QueueFull):
            return False

    async def dequeue(self):
        return await self.queue.get()

    def size(self) -> int:
        return self.queue.qsize()

    def is_full(self) -> bool:
        return self.queue.full()
