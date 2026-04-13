import math
from app.core.config import settings


class AnomalyAgent:
    def can_handle(self, event):
        return event.get("type") == "history"

    async def process(self, event):
        history = event.get("event_history", [])
        result = detect_anomaly(history)

        return {
            "agent": "anomaly",
            "anomaly_detected": result["detected"],
            "method": result["method"],
            "details": result["details"],
            "risk_score": 5 if result["detected"] else 0,
        }


def detect_anomaly(event_history: list[dict]) -> dict:
    """
    Leave-one-out z-score anomaly detection.

    The peak value is scored against the baseline statistics computed from
    all *other* samples.  This prevents the outlier from contaminating its
    own mean/stddev, giving a much more sensitive signal.

    Falls back to a simple ratio check when the baseline is flat (stddev == 0).

    Returns a dict with keys: detected, method, details.
    """
    min_history = settings.ANOMALY_MIN_HISTORY
    if len(event_history) < min_history:
        return {"detected": False, "method": "none", "details": {"reason": "insufficient_history"}}

    rates = [e["event_rate"] for e in event_history if "event_rate" in e]
    if len(rates) < min_history:
        return {"detected": False, "method": "none", "details": {"reason": "insufficient_rates"}}

    peak = max(rates)

    # Baseline: all samples except the peak occurrence
    peak_idx = rates.index(peak)
    baseline = rates[:peak_idx] + rates[peak_idx + 1:]

    if not baseline:
        return {"detected": False, "method": "none", "details": {"reason": "single_sample"}}

    n = len(baseline)
    mean = sum(baseline) / n
    variance = sum((r - mean) ** 2 for r in baseline) / n
    stddev = math.sqrt(variance)

    if stddev > 0:
        z_peak = (peak - mean) / stddev
        detected = z_peak > settings.ANOMALY_ZSCORE_THRESHOLD
        return {
            "detected": detected,
            "method": "zscore_loo",
            "details": {
                "baseline_mean": round(mean, 2),
                "baseline_stddev": round(stddev, 2),
                "peak": peak,
                "z_score": round(z_peak, 2),
                "threshold": settings.ANOMALY_ZSCORE_THRESHOLD,
            },
        }

    # Fallback: ratio check when baseline is flat
    detected = mean > 0 and peak > settings.ANOMALY_SPIKE_RATIO * mean
    return {
        "detected": detected,
        "method": "ratio",
        "details": {
            "baseline_mean": round(mean, 2),
            "peak": peak,
            "ratio": round(peak / mean, 2) if mean else 0,
            "threshold": settings.ANOMALY_SPIKE_RATIO,
        },
    }
