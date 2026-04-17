from app.services.mitre_mapper import map_flags_to_techniques


class PhishingAgent:
    """Detects phishing interaction signals."""

    def can_handle(self, event: dict) -> bool:
        return event.get("type") == "phishing_click"

    async def process(self, event: dict) -> dict:
        flags: list[str] = []
        risk = 0

        if event.get("url"):
            flags.append("PHISHING_URL")
            risk += 3

        if event.get("auto_click"):
            flags.append("AUTO_CLICK")
            risk += 4

        if event.get("outside_app_context"):
            flags.append("OUT_OF_CONTEXT_CLICK")
            risk += 2

        return {
            "agent": "phishing",
            "flags": flags,
            "risk_score": risk,
            "mitre_techniques": map_flags_to_techniques(flags),
        }
