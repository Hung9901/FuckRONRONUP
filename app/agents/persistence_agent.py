from app.services.mitre_mapper import map_flags_to_techniques


class PersistenceAgent:
    """Detects boot-persistence and foreground-service abuse."""

    def can_handle(self, event: dict) -> bool:
        return event.get("type") in ("lifecycle", "background_activity")

    async def process(self, event: dict) -> dict:
        flags: list[str] = []

        if event.get("boot_trigger"):
            flags.append("BOOT_START")
        if event.get("restart_count", 0) > 3:
            flags.append("RESTART_LOOP")
        if event.get("foreground_service_long"):
            flags.append("LONG_RUNNING_SERVICE")

        return {
            "agent": "persistence",
            "flags": flags,
            "risk_score": len(flags) * 2,
            "mitre_techniques": map_flags_to_techniques(flags),
        }
