class ExfilAgent:
    """
    Detects network-level data exfiltration patterns.

    Handles events of type 'data_transfer' or 'network'.
    Scored signals:
      - large outbound payload
      - connection to an unknown/external host
      - upload during background/off-hours activity
      - repeated transfer bursts
    """

    def can_handle(self, event: dict) -> bool:
        return event.get("type") in ("data_transfer", "network")

    async def process(self, event: dict) -> dict:
        flags: list[str] = []
        risk = 0

        if event.get("bytes_sent", 0) > 500_000:
            flags.append("LARGE_PAYLOAD")
            risk += 3

        if event.get("external_host") and not event.get("known_host"):
            flags.append("UNKNOWN_EXTERNAL_HOST")
            risk += 3

        if event.get("background_transfer"):
            flags.append("BACKGROUND_TRANSFER")
            risk += 2

        burst_count = event.get("burst_count", 0)
        if burst_count > 5:
            flags.append("TRANSFER_BURST")
            risk += min(burst_count // 5, 3)  # cap at +3

        return {
            "agent": "exfil",
            "flags": flags,
            "risk_score": risk,
        }
