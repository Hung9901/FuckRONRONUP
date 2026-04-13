import os


class Settings:
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "100"))
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    QUEUE_MAXSIZE: int = int(os.getenv("QUEUE_MAXSIZE", "100000"))
    QUEUE_ENQUEUE_TIMEOUT: float = float(os.getenv("QUEUE_ENQUEUE_TIMEOUT", "5.0"))
    # Risk thresholds
    RISK_CRITICAL: int = int(os.getenv("RISK_CRITICAL", "20"))
    RISK_HIGH: int = int(os.getenv("RISK_HIGH", "10"))
    RISK_MEDIUM: int = int(os.getenv("RISK_MEDIUM", "5"))
    # Anomaly detection
    ANOMALY_SPIKE_RATIO: float = float(os.getenv("ANOMALY_SPIKE_RATIO", "3.0"))
    ANOMALY_ZSCORE_THRESHOLD: float = float(os.getenv("ANOMALY_ZSCORE_THRESHOLD", "2.5"))
    ANOMALY_MIN_HISTORY: int = int(os.getenv("ANOMALY_MIN_HISTORY", "5"))
    # Sequence detection time window (seconds); 0 = disabled
    CHAIN_TIME_WINDOW: float = float(os.getenv("CHAIN_TIME_WINDOW", "0"))


settings = Settings()
