from pydantic import BaseModel, Field
from typing import Any


class EventPayload(BaseModel):
    type: str
    ts: float | None = None

    model_config = {"extra": "allow"}


class AgentResult(BaseModel):
    agent: str
    risk_score: int = 0
    flags: list[str] = Field(default_factory=list)


class RiskSnapshot(BaseModel):
    device_id: str
    total_risk: int
    threat_level: str
    active_signals: list[str]
    agent_hits: dict[str, int] = Field(default_factory=dict)


class GraphResult(BaseModel):
    graph_score: int
    matched_nodes: list[str]
    full_chain_detected: bool
    coverage: float


class ChainResponse(BaseModel):
    device_id: str
    risk_score: int
    threat_level: str
    detected_pattern: str
    sequence_detected: bool
    signals: list[str]
    graph: GraphResult
    timeline: list[dict[str, Any]]


class SimulateResponse(BaseModel):
    event: dict[str, Any]
    agent_results: list[dict[str, Any]]
    risk: RiskSnapshot


class HealthResponse(BaseModel):
    status: str
    queue_size: int | None = None
