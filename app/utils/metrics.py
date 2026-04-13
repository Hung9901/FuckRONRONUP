"""
Lightweight in-process metrics — no external dependencies required.

Exposes counters and histograms that can be read via GET /metrics.
For production, swap this module out for prometheus_client or
opentelemetry-sdk and keep the same call sites.
"""

import time
from collections import defaultdict
from threading import Lock


class _Counter:
    def __init__(self):
        self._value = 0
        self._lock = Lock()

    def inc(self, amount: int = 1) -> None:
        with self._lock:
            self._value += amount

    def value(self) -> int:
        return self._value


class _Histogram:
    """Records observed values and exposes p50 / p95 / p99 approximations."""

    def __init__(self):
        self._observations: list[float] = []
        self._lock = Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._observations.append(value)
            # Cap memory: keep last 10 000 observations
            if len(self._observations) > 10_000:
                self._observations = self._observations[-10_000:]

    def summary(self) -> dict:
        with self._lock:
            data = sorted(self._observations)
        if not data:
            return {"count": 0, "p50": None, "p95": None, "p99": None}
        n = len(data)
        return {
            "count": n,
            "p50": data[int(n * 0.50)],
            "p95": data[int(n * 0.95)],
            "p99": data[int(n * 0.99)],
        }


# ------------------------------------------------------------------
# Global metric instances
# ------------------------------------------------------------------

messages_received   = _Counter()      # Total WebSocket messages received
events_processed    = _Counter()      # Total events routed through the pipeline
events_dropped      = _Counter()      # Events dropped due to a full queue
agent_errors        = _Counter()      # Exceptions caught in Worker.process()
processing_latency  = _Histogram()    # End-to-end latency per event (seconds)


def snapshot() -> dict:
    """Return a point-in-time snapshot of all metrics."""
    return {
        "messages_received":  messages_received.value(),
        "events_processed":   events_processed.value(),
        "events_dropped":     events_dropped.value(),
        "agent_errors":       agent_errors.value(),
        "processing_latency": processing_latency.summary(),
    }
