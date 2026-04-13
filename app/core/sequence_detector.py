"""
Sequence-based attack chain detector.

Attackers rely on timing + ordering, not just isolated events.
This module checks whether a session's event log contains the
ordered fingerprint of a full mobile attack chain.
"""

from app.core.attack_graph import AttackGraph

# The ordered event-type fingerprint for the full phishing → exfil chain.
FULL_CHAIN_PATTERN: list[str] = [
    "phishing_click",
    "permission_request",
    "accessibility_enabled",
    "background_activity",
    "data_transfer",
]

# Map raw event types → AttackGraph signal names so both systems stay in sync.
EVENT_TO_SIGNAL: dict[str, str] = {
    "phishing_click":        AttackGraph.PHISHING_INTERACTION,
    "permission_request":    AttackGraph.PERMISSION_ESCALATION,
    "permission":            AttackGraph.PERMISSION_ESCALATION,
    "accessibility_enabled": AttackGraph.ACCESSIBILITY_RISK,
    "accessibility":         AttackGraph.ACCESSIBILITY_RISK,
    "background_activity":   AttackGraph.PERSISTENCE_PATTERN,
    "lifecycle":             AttackGraph.PERSISTENCE_PATTERN,
    "data_transfer":         AttackGraph.EXFIL_PATTERN,
    "network":               AttackGraph.EXFIL_PATTERN,
}


def detect_attack_sequence(events: list[dict]) -> bool:
    """
    Return True if *every* step of FULL_CHAIN_PATTERN appears in the
    session event log (order-insensitive presence check — real deployments
    should add a time-window constraint on top).
    """
    seen = {e["type"] for e in events}
    return all(step in seen for step in FULL_CHAIN_PATTERN)


def events_to_signals(events: list[dict]) -> set[str]:
    """Translate a session event list into AttackGraph signal names."""
    signals: set[str] = set()
    for event in events:
        signal = EVENT_TO_SIGNAL.get(event.get("type", ""))
        if signal:
            signals.add(signal)
    return signals
