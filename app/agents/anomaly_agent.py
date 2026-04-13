class AnomalyAgent:
    def can_handle(self, event):
        return event.get("type") == "history"

    async def process(self, event):
        history = event.get("event_history", [])
        anomaly = detect_anomaly(history)

        return {
            "agent": "anomaly",
            "anomaly_detected": anomaly,
            "risk_score": 5 if anomaly else 0,
        }


def detect_anomaly(event_history):
    if len(event_history) < 5:
        return False

    rates = [e["event_rate"] for e in event_history if "event_rate" in e]
    if not rates:
        return False

    avg = sum(rates) / len(rates)
    return avg > 0 and max(rates) > 3 * avg
