class AccessibilityAgent:
    def can_handle(self, event):
        return event.get("type") in ("accessibility", "accessibility_enabled")

    async def process(self, event):
        risk = 0

        if event.get("enabled"):
            risk += 2
        if not event.get("declared_use"):
            risk += 3
        if event.get("event_rate", 0) > 100:
            risk += 2

        return {
            "agent": "accessibility",
            "risk_score": risk,
            "severity": self.classify(risk),
        }

    def classify(self, score):
        if score >= 6:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        return "LOW"
