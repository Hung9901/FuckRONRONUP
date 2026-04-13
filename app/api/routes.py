import time
from fastapi import APIRouter
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
from app.core.attack_graph import AttackGraph
from app.core.sequence_detector import detect_attack_sequence, detect_attack_sequence_windowed, events_to_signals
from app.core.logging import get_logger
from app.api.websocket import manager
from app.utils import metrics

router = APIRouter()
sim = SimulationEngine()
log = get_logger(__name__)

# Shared orchestrator and aggregator for HTTP simulate routes
_orchestrator = Orchestrator([
    PhishingAgent(), AccessibilityAgent(), PersistenceAgent(),
    PermissionAgent(), AnomalyAgent(), ExfilAgent(), UIAgent(),
])
_aggregator = RiskAggregator()
_graph = AttackGraph()


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

    Returns:
    - per-event agent results
    - sequence detection (ordered presence check)
    - attack graph evaluation (weighted node scoring)
    - final aggregated risk with threat level
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

    log.info(
        "simulate_chain",
        extra={
            "chain_detected": chain_detected,
            "graph_score": graph_result["graph_score"],
            "threat_level": final_risk["threat_level"],
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
    return {"event": event, "agent_results": results, "risk": risk}


@router.post("/reset/{device_id}")
async def reset_device(device_id: str):
    """Clear accumulated risk scores and signals for a device."""
    _aggregator.reset(device_id)
    return {"reset": device_id}


@router.get("/metrics")
async def get_metrics():
    """In-process pipeline metrics snapshot."""
    return metrics.snapshot()
