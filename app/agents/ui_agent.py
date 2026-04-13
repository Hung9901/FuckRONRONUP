class UIAgent:
    """
    Detects UI manipulation and overlay-based attack patterns.

    Handles events of type 'ui'.
    Scored signals:
      - screen overlay (clickjacking / tapjacking)
      - fake system dialog rendered over a real app
      - draw-over-apps permission combined with input capture
      - invisible touch interception
    """

    def can_handle(self, event: dict) -> bool:
        return event.get("type") == "ui"

    async def process(self, event: dict) -> dict:
        flags: list[str] = []
        risk = 0

        if event.get("overlay_detected"):
            flags.append("OVERLAY_ATTACK")
            risk += 3

        if event.get("fake_system_dialog"):
            flags.append("FAKE_DIALOG")
            risk += 4

        if event.get("draw_over_apps") and event.get("input_capture"):
            flags.append("TAPJACKING")
            risk += 4

        if event.get("invisible_touch_intercept"):
            flags.append("INVISIBLE_INTERCEPT")
            risk += 3

        return {
            "agent": "ui",
            "flags": flags,
            "risk_score": risk,
        }
