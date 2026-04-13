class PersistenceAgent:
    def can_handle(self, event):
        return event.get("type") in ("lifecycle", "background_activity")

    async def process(self, event):
        flags = []

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
        }
