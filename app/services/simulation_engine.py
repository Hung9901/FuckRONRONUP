import asyncio
import time


class SimulationEngine:
    """Generates synthetic threat scenarios for pipeline testing."""

    # ------------------------------------------------------------------
    # Individual scenario generators
    # ------------------------------------------------------------------

    def generate_accessibility_attack(self) -> dict:
        return {
            "type": "accessibility",
            "enabled": True,
            "declared_use": False,
            "event_rate": 150,
            "ts": time.time(),
        }

    def generate_persistence_pattern(self) -> dict:
        return {
            "type": "lifecycle",
            "boot_trigger": True,
            "restart_count": 5,
            "foreground_service_long": True,
            "ts": time.time(),
        }

    def generate_permission_escalation(self) -> dict:
        return {
            "type": "permission",
            "permissions": ["READ_CONTACTS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"],
            "escalation_sequence": ["READ_CONTACTS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"],
            "ts": time.time(),
        }

    def generate_anomaly_burst(self) -> dict:
        return {
            "type": "history",
            "event_history": [
                {"event_rate": 10},
                {"event_rate": 12},
                {"event_rate": 9},
                {"event_rate": 11},
                {"event_rate": 10},
                {"event_rate": 200},  # spike
            ],
            "ts": time.time(),
        }

    def generate_exfil_transfer(self) -> dict:
        return {
            "type": "data_transfer",
            "bytes_sent": 1_200_000,
            "external_host": True,
            "known_host": False,
            "background_transfer": True,
            "burst_count": 8,
            "ts": time.time(),
        }

    def generate_ui_attack(self) -> dict:
        return {
            "type": "ui",
            "overlay_detected": True,
            "fake_system_dialog": True,
            "draw_over_apps": True,
            "input_capture": True,
            "invisible_touch_intercept": False,
            "ts": time.time(),
        }

    def generate_phishing_click(self) -> dict:
        return {
            "type": "phishing_click",
            "url": "http://fake-update.example.com",
            "auto_click": False,
            "outside_app_context": True,
            "ts": time.time(),
        }

    # ------------------------------------------------------------------
    # Phishing chain — ordered event sequence
    # ------------------------------------------------------------------

    def phishing_chain(self) -> list[dict]:
        """
        Returns the ordered event sequence that maps to the full attack chain:
          PHISHING_INTERACTION → PERMISSION_ESCALATION → ACCESSIBILITY_RISK
                                           ↓
                                  PERSISTENCE_PATTERN
                                           ↓
                                    EXFIL_PATTERN
        """
        base_ts = time.time()
        return [
            {"type": "phishing_click", "url": "http://fake-update.example.com", "ts": base_ts},
            {
                "type": "permission_request",
                "permissions": ["READ_CONTACTS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"],
                "escalation_sequence": ["READ_CONTACTS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"],
                "ts": base_ts + 5,
            },
            {
                "type": "accessibility_enabled",
                "enabled": True,
                "declared_use": False,
                "event_rate": 180,
                "ts": base_ts + 12,
            },
            {
                "type": "background_activity",
                "boot_trigger": True,
                "restart_count": 6,
                "foreground_service_long": True,
                "ts": base_ts + 20,
            },
            {
                "type": "data_transfer",
                "bytes_sent": 2_000_000,
                "external_host": True,
                "known_host": False,
                "background_transfer": True,
                "burst_count": 10,
                "ts": base_ts + 30,
            },
        ]

    # ------------------------------------------------------------------
    # Convenience collections
    # ------------------------------------------------------------------

    def all_scenarios(self) -> list[dict]:
        return [
            self.generate_phishing_click(),
            self.generate_accessibility_attack(),
            self.generate_persistence_pattern(),
            self.generate_permission_escalation(),
            self.generate_anomaly_burst(),
            self.generate_exfil_transfer(),
            self.generate_ui_attack(),
        ]

    # ------------------------------------------------------------------
    # Timed simulation runner
    # ------------------------------------------------------------------

    async def run_scenario(
        self,
        events: list[dict],
        callback,
        delay: float = 1.0,
    ) -> list:
        """
        Replay a scenario event-by-event with a simulated time delay.

        Args:
            events:   Ordered list of events to replay.
            callback: Async callable(event) → result invoked for each event.
            delay:    Seconds between events (default 1 s).

        Returns:
            List of callback results in order.
        """
        results = []
        for event in events:
            result = await callback(event)
            results.append(result)
            await asyncio.sleep(delay)
        return results
