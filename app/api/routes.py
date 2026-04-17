import time
from fastapi import APIRouter, HTTPException
from app.services.simulation_engine import SimulationEngine
from app.agents.orchestrator import Orchestrator
from app.agents.accessibility_agent import AccessibilityAgent
from app.agents.persistence_agent import PersistenceAgent
from app.agents.permission_agent import PermissionAgent
from app.agents.anomaly_agent import AnomalyAgent
from app.agents.exfil_agent import ExfilAgent
from app.agents.ui_agent import UIAgent
from app.agents.phishing_agent import PhishingAgent
from app.services.risk_aggregator import RiskAggregator
from app.services.ai_analyst import analyze_threat
from app.services.alert_manager import AlertManager
from app.services.mitre_mapper import map_flags_to_techniques, all_techniques_from_context
from app.core.attack_graph import AttackGraph
from app.core.sequence_detector import detect_attack_sequence, detect_attack_sequence_windowed, events_to_signals
from app.core.logging import get_logger
from app.api.websocket import manager
from app.models.schemas import WebhookRegistration, AIAnalysisRequest
from app.utils import metrics

router = APIRouter()
sim = SimulationEngine()
log = get_logger(__name__)

_orchestrator = Orchestrator([
    PhishingAgent(), AccessibilityAgent(), PersistenceAgent(),
    PermissionAgent(), AnomalyAgent(), ExfilAgent(), UIAgent(),
])
_aggregator = RiskAggregator()
_graph = AttackGraph()
_alert_manager = AlertManager()


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "queue_size": manager.queue_size(),
    }


@router.post("/simulate/all")
async def simulate_all():
    _aggregator.reset("simulation_all")
    events = sim.all_scenarios()
    all_results = []
    risk = {}
    for event in events:
        t0 = time.monotonic()
        results = await _orchestrator.route(event)
        metrics.events_processed.inc()
        metrics.processing_latency.observe(time.monotonic() - t0)
        for r in results:
            risk = await _aggregator.update("simulation_all", r)
        all_results.append({"event": event, "results": results})
    log.info("simulate_all", extra={"event_count": len(events), "final_risk": risk.get("total_risk")})
    return {"scenarios": all_results, "final_risk": risk}


@router.post("/simulate/chain")
async def simulate_chain():
    """
    Runs the full phishing → exfil attack chain through the pipeline.

    Returns per-event agent results, sequence detection, attack graph evaluation,
    final aggregated risk, MITRE technique coverage, and webhook alert receipts.
    """
    _aggregator.reset("chain")
    events = sim.phishing_chain()
    timeline = []

    for event in events:
        t0 = time.monotonic()
        results = await _orchestrator.route(event)
        metrics.events_processed.inc()
        metrics.processing_latency.observe(time.monotonic() - t0)
        risk = {}
        for r in results:
            risk = await _aggregator.update("chain", r)
        timeline.append({"event": event, "agent_results": results, "risk_snapshot": risk})

    chain_detected = detect_attack_sequence(events)
    chain_detected_windowed = detect_attack_sequence_windowed(events)

    active_signals = events_to_signals(events)
    graph_result = _graph.evaluate(active_signals)
    final_risk = _aggregator.get("chain")

    # Collect all flags from the timeline for MITRE mapping
    all_flags: list[str] = []
    for entry in timeline:
        for agent_result in entry.get("agent_results", []):
            all_flags.extend(agent_result.get("flags", []))

    mitre_techniques = all_techniques_from_context(all_flags, active_signals)

    context = {
        "device_id": "chain",
        "sequence_detected": chain_detected,
        "sequence_detected_windowed": chain_detected_windowed,
        "detected_pattern": "FULL_ATTACK_CHAIN" if chain_detected else "PARTIAL",
        "graph": graph_result,
        "timeline": timeline,
        "risk_snapshot": final_risk,
    }

    # Fire webhook alerts asynchronously
    alert_receipts = await _alert_manager.trigger(
        {
            "device_id": "chain",
            "threat_level": final_risk["threat_level"],
            "total_risk": final_risk["total_risk"],
            "active_signals": list(active_signals),
            "agent_hits": final_risk.get("agent_hits", {}),
        },
        context,
    )

    log.info(
        "simulate_chain",
        extra={
            "chain_detected": chain_detected,
            "graph_score": graph_result["graph_score"],
            "threat_level": final_risk["threat_level"],
            "mitre_count": len(mitre_techniques),
            "alerts_sent": len(alert_receipts),
        },
    )

    return {
        "device_id": "chain",
        "risk_score": final_risk["total_risk"],
        "threat_level": final_risk["threat_level"],
        "detected_pattern": "FULL_ATTACK_CHAIN" if chain_detected else "PARTIAL",
        "sequence_detected": chain_detected,
        "sequence_detected_windowed": chain_detected_windowed,
        "signals": list(active_signals),
        "graph": graph_result,
        "timeline": timeline,
        "mitre_techniques": mitre_techniques,
        "alert_receipts": alert_receipts,
    }


@router.post("/simulate/{scenario}")
async def simulate(scenario: str):
    generators = {
        "accessibility": sim.generate_accessibility_attack,
        "persistence":   sim.generate_persistence_pattern,
        "permission":    sim.generate_permission_escalation,
        "anomaly":       sim.generate_anomaly_burst,
        "exfil":         sim.generate_exfil_transfer,
        "ui":            sim.generate_ui_attack,
        "phishing":      sim.generate_phishing_click,
    }
    if scenario not in generators:
        return {"error": "unknown scenario", "available": list(generators)}

    _aggregator.reset("simulation")
    event = generators[scenario]()
    t0 = time.monotonic()
    results = await _orchestrator.route(event)
    metrics.events_processed.inc()
    metrics.processing_latency.observe(time.monotonic() - t0)
    risk = {}
    for r in results:
        risk = await _aggregator.update("simulation", r)

    # Single-scenario MITRE coverage: map directly from agent flags.
    # RiskAggregator.active_signals stores agent flag strings (e.g. PHISHING_URL,
    # SENSITIVE_READ_CONTACTS) — FLAG_TO_MITRE is the correct lookup table.
    # SIGNAL_TO_MITRE is for attack-graph signal names (PHISHING_INTERACTION,
    # EXFIL_PATTERN, etc.) which are only produced in the full chain route.
    mitre_techniques = map_flags_to_techniques(risk.get("active_signals", []))

    return {"event": event, "agent_results": results, "risk": risk, "mitre_techniques": mitre_techniques}


# ── AI Analysis ───────────────────────────────────────────────────────────────

@router.post("/analyze/ai")
async def ai_analyze(request: AIAnalysisRequest):
    """Run Claude Opus 4.7 threat intelligence analysis on arbitrary detection context."""
    report = await analyze_threat(request.context)
    return report


# ── Webhook Alert Management ──────────────────────────────────────────────────

@router.post("/alerts/webhook")
async def register_webhook(reg: WebhookRegistration):
    """Register a webhook endpoint for threat alerts."""
    wid = _alert_manager.register(reg.url, reg.min_severity, reg.description)
    return {"webhook_id": wid, "registered": True, "url": reg.url, "min_severity": reg.min_severity}


@router.get("/alerts/webhooks")
async def list_webhooks():
    """List all registered webhook endpoints."""
    return {"webhooks": _alert_manager.list_webhooks()}


@router.delete("/alerts/webhook/{webhook_id}")
async def unregister_webhook(webhook_id: str):
    """Unregister a webhook endpoint."""
    removed = _alert_manager.unregister(webhook_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"removed": True, "webhook_id": webhook_id}


# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────

@router.get("/mitre/techniques")
async def list_mitre_techniques():
    """Return the full MITRE ATT&CK for Mobile technique catalogue."""
    from app.services.mitre_mapper import MITRE_TECHNIQUES, TACTIC_ORDER
    techniques = [
        {"id": tid, **data}
        for tid, data in MITRE_TECHNIQUES.items()
    ]
    return {
        "techniques": sorted(
            techniques,
            key=lambda t: (
                TACTIC_ORDER.index(t["tactic"]) if t["tactic"] in TACTIC_ORDER else 99,
                t["id"],
            ),
        ),
        "total": len(techniques),
    }


# ── Fleet Overview ────────────────────────────────────────────────────────────

@router.get("/fleet")
async def fleet_overview():
    """Return risk snapshots for all tracked devices."""
    snapshots = _aggregator.get_all()
    return {
        "devices": list(snapshots.values()),
        "total": len(snapshots),
        "critical_count": sum(1 for d in snapshots.values() if d.get("threat_level") == "CRITICAL"),
        "high_count": sum(1 for d in snapshots.values() if d.get("threat_level") == "HIGH"),
    }


# ── Other ─────────────────────────────────────────────────────────────────────

@router.post("/reset/{device_id}")
async def reset_device(device_id: str):
    """Clear accumulated risk scores and signals for a device."""
    _aggregator.reset(device_id)
    return {"reset": device_id}


@router.get("/metrics")
async def get_metrics():
    """In-process pipeline metrics snapshot."""
    return metrics.snapshot()
