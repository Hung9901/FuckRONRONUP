"""
Sequence-based attack chain detector.

Attackers rely on timing + ordering, not just isolated events.
This module checks whether a session's event log contains the
ordered fingerprint of a full mobile attack chain.

Two detection modes:
  - detect_attack_sequence: strict ordering check (each step must appear
    after the previous one in the event list).
  - detect_attack_sequence_windowed: same ordering check but also enforces
    that the entire chain completes within a configurable time window
    (requires events to carry a "ts" field in Unix seconds).
"""

from __future__ import annotations

import time
from app.core.attack_graph import AttackGraph
from app.core.config import settings

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
    "ui":                    AttackGraph.UI_ATTACK,
}


def detect_attack_sequence(events: list[dict]) -> bool:
    """
    Return True if every step of FULL_CHAIN_PATTERN appears **in order**
    in the session event log.

    This is an O(n) scan: we advance through the pattern list as each
    required step is found, ensuring ordering is respected.
    """
    pattern = FULL_CHAIN_PATTERN
    step = 0
    for event in events:
        if step >= len(pattern):
            break
        if event.get("type") == pattern[step]:
            step += 1
    return step == len(pattern)


def detect_attack_sequence_windowed(
    events: list[dict],
    window_seconds: float | None = None,
) -> bool:
    """
    Order-aware detection with an optional time window constraint.

    Each event must carry a "ts" key (Unix timestamp, float).
    The window is measured from the first matched step to the last.

    Args:
        events:         Ordered list of session events.
        window_seconds: Maximum allowed duration (seconds) for the full
                        chain to complete.  None / 0 disables the check.

    Returns:
        True if the full chain is detected in order (and within the window).
    """
    if window_seconds is None:
        window_seconds = settings.CHAIN_TIME_WINDOW

    pattern = FULL_CHAIN_PATTERN
    step = 0
    first_ts: float | None = None
    last_ts: float | None = None

    for event in events:
        if step >= len(pattern):
            break
        if event.get("type") == pattern[step]:
            ts = event.get("ts", time.time())
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            step += 1

    if step < len(pattern):
        return False

    if window_seconds and first_ts is not None and last_ts is not None:
        return (last_ts - first_ts) <= window_seconds

    return True


def events_to_signals(events: list[dict]) -> set[str]:
    """Translate a session event list into AttackGraph signal names."""
    signals: set[str] = set()
    for event in events:
        signal = EVENT_TO_SIGNAL.get(event.get("type", ""))
        if signal:
            signals.add(signal)
    return signals
