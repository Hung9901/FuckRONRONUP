"""
Webhook Alert Manager — httpx-based async delivery with retry + rate-limiting.

Webhooks are registered with a minimum severity threshold.  When a simulation
crosses the threshold the manager fans out to all matching endpoints, retrying
up to ALERT_MAX_RETRIES times with exponential backoff, and rate-limits alerts
to one per device per ALERT_RATE_LIMIT_SECONDS to prevent spam.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass
class WebhookConfig:
    id: str
    url: str
    min_severity: str = "HIGH"
    description: str = ""
    created_at: float = field(default_factory=time.time)


class AlertManager:
    """Thread-safe in-memory webhook registry with async delivery."""

    def __init__(self) -> None:
        self._webhooks: dict[str, WebhookConfig] = {}
        self._last_alert: dict[str, float] = {}  # device_id → last-alert epoch

    # ── Registry ──────────────────────────────────────────────────────────────

    def register(self, url: str, min_severity: str = "HIGH", description: str = "") -> str:
        """Register a webhook. Returns the webhook ID (stable hash of URL)."""
        wid = hashlib.sha256(url.encode()).hexdigest()[:12]
        self._webhooks[wid] = WebhookConfig(
            id=wid, url=url, min_severity=min_severity.upper(), description=description
        )
        log.info("webhook_registered", extra={"id": wid, "url": url, "min_severity": min_severity})
        return wid

    def unregister(self, webhook_id: str) -> bool:
        removed = self._webhooks.pop(webhook_id, None)
        if removed:
            log.info("webhook_unregistered", extra={"id": webhook_id})
        return removed is not None

    def list_webhooks(self) -> list[dict]:
        return [
            {
                "id": w.id,
                "url": w.url,
                "min_severity": w.min_severity,
                "description": w.description,
                "created_at": w.created_at,
            }
            for w in self._webhooks.values()
        ]

    # ── Delivery ──────────────────────────────────────────────────────────────

    async def trigger(self, risk_snapshot: dict, context: dict | None = None) -> list[dict]:
        """
        Fan-out alert to all webhooks whose min_severity ≤ current threat level.
        Respects per-device rate limiting.  Returns delivery receipts.
        """
        device_id    = risk_snapshot.get("device_id", "unknown")
        threat_level = risk_snapshot.get("threat_level", "LOW")
        rank         = _SEVERITY_RANK.get(threat_level, 0)

        # Rate-limit: one alert per device per configured window
        now = time.time()
        last = self._last_alert.get(device_id, 0.0)
        if now - last < settings.ALERT_RATE_LIMIT_SECONDS:
            log.info("alert_rate_limited", extra={"device_id": device_id})
            return []

        eligible = [
            w for w in self._webhooks.values()
            if rank >= _SEVERITY_RANK.get(w.min_severity, 2)
        ]
        if not eligible:
            return []

        self._last_alert[device_id] = now

        payload = {
            "alert_type": "THREAT_DETECTED",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "device_id": device_id,
            "threat_level": threat_level,
            "risk_score": risk_snapshot.get("total_risk", 0),
            "active_signals": risk_snapshot.get("active_signals", []),
            "agent_hits": risk_snapshot.get("agent_hits", {}),
            "context_summary": {
                "sequence_detected": (context or {}).get("sequence_detected", False),
                "graph_score": (context or {}).get("graph", {}).get("graph_score", 0),
                "full_chain": (context or {}).get("graph", {}).get("full_chain_detected", False),
            },
        }

        tasks = [self._deliver(w, payload) for w in eligible]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        receipts = []
        for w, res in zip(eligible, results):
            if isinstance(res, Exception):
                receipts.append({"webhook_id": w.id, "url": w.url, "status": "error", "error": str(res)})
            else:
                receipts.append(res)
        return receipts

    async def _deliver(self, webhook: WebhookConfig, payload: dict) -> dict:
        """POST payload to a single webhook with exponential-backoff retry.

        A single AsyncClient is created for the entire delivery so all retry
        attempts share the same connection pool rather than opening a new TCP
        connection on every attempt.
        """
        last_exc: Exception | None = None
        async with httpx.AsyncClient(timeout=settings.ALERT_WEBHOOK_TIMEOUT) as client:
            for attempt in range(settings.ALERT_MAX_RETRIES):
                try:
                    r = await client.post(
                        webhook.url,
                        json=payload,
                        headers={"Content-Type": "application/json", "X-Source": "SENTINEL-ThreatDetection"},
                    )
                    log.info(
                        "webhook_delivered",
                        extra={"id": webhook.id, "status": r.status_code, "attempt": attempt + 1},
                    )
                    return {"webhook_id": webhook.id, "url": webhook.url, "status": r.status_code, "attempt": attempt + 1}
                except Exception as exc:
                    last_exc = exc
                    wait = 2 ** attempt
                    log.warning(
                        "webhook_retry",
                        extra={"id": webhook.id, "attempt": attempt + 1, "error": str(exc), "wait_s": wait},
                    )
                    if attempt < settings.ALERT_MAX_RETRIES - 1:
                        await asyncio.sleep(wait)

        return {"webhook_id": webhook.id, "url": webhook.url, "status": "failed", "error": str(last_exc)}
