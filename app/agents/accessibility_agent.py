from app.services.mitre_mapper import map_flags_to_techniques


class AccessibilityAgent:
    """Detects accessibility service abuse."""

    def can_handle(self, event: dict) -> bool:
        return event.get("type") in ("accessibility", "accessibility_enabled")

    async def process(self, event: dict) -> dict:
        risk = 0
        flags: list[str] = []

        if event.get("enabled"):
            risk += 2

        if not event.get("declared_use"):
            risk += 3
            flags.append("UNDECLARED_ACCESSIBILITY_USE")

        if event.get("event_rate", 0) > 100:
            risk += 2
            flags.append("HIGH_EVENT_RATE")

        if risk >= 3:
            flags.append("ACCESSIBILITY_RISK")

        return {
            "agent": "accessibility",
            "flags": flags,
            "risk_score": risk,
            "severity": self.classify(risk),
            "mitre_techniques": map_flags_to_techniques(flags),
        }

    def classify(self, score: int) -> str:
        if score >= 6:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        return "LOW"
