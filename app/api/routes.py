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
from app.core.sequence_detector import detect_attack_sequence, events_to_signals

router = APIRouter()
sim = SimulationEngine()
_orchestrator = Orchestrator([
    PhishingAgent(), AccessibilityAgent(), PersistenceAgent(),
    PermissionAgent(), AnomalyAgent(), ExfilAgent(), UIAgent(),
])
_aggregator = RiskAggregator()
_graph = AttackGraph()


@router.get("/health")
async def health_check():
    return {"status": "ok"}


# Fixed-path routes MUST come before /{scenario} to avoid being swallowed
@router.post("/simulate/all")
async def simulate_all():
    events = sim.all_scenarios()
    all_results = []
    risk = {}
    for event in events:
        results = await _orchestrator.route(event)
        for r in results:
            risk = await _aggregator.update("simulation_all", r)
        all_results.append({"event": event, "results": results})
    return {"scenarios": all_results, "final_risk": risk}


@router.post("/simulate/chain")
async def simulate_chain():
    """
    Runs the full phishing → exfil attack chain through the pipeline.

    Returns:
    - per-event agent results
    - sequence detection (all chain steps present?)
    - attack graph evaluation (weighted node scoring)
    - final aggregated risk with threat level
    """
    _aggregator.reset("chain")
    events = sim.phishing_chain()
    timeline = []

    for event in events:
        results = await _orchestrator.route(event)
        risk = {}
        for r in results:
            risk = await _aggregator.update("chain", r)
        timeline.append({"event": event, "agent_results": results, "risk_snapshot": risk})

    # Sequence detection
    chain_detected = detect_attack_sequence(events)

    # Attack graph evaluation
    active_signals = events_to_signals(events)
    graph_result = _graph.evaluate(active_signals)

    final_risk = _aggregator.get("chain")

    return {
        "device_id": "chain",
        "risk_score": final_risk["total_risk"],
        "threat_level": final_risk["threat_level"],
        "detected_pattern": "FULL_ATTACK_CHAIN" if chain_detected else "PARTIAL",
        "sequence_detected": chain_detected,
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
    }
    if scenario not in generators:
        return {"error": "unknown scenario", "available": list(generators)}

    event = generators[scenario]()
    results = await _orchestrator.route(event)
    risk = {}
    for r in results:
        risk = await _aggregator.update("simulation", r)
    return {"event": event, "agent_results": results, "risk": risk}
