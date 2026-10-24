import time
from collections import deque
from dataclasses import asdict, dataclass, field

MAX_ALERTS = 200


@dataclass
class Alert:
    timestamp: float
    source: str
    severity: str
    message: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AlertStore:
    def __init__(self, max_alerts: int = MAX_ALERTS):
        self._alerts: deque[Alert] = deque(maxlen=max_alerts)

    def add(self, source: str, severity: str, message: str, **details) -> Alert:
        alert = Alert(
            timestamp=time.time(),
            source=source,
            severity=severity,
            message=message,
            details=details,
        )
        self._alerts.append(alert)
        return alert

    def list(self) -> list[dict]:
        return [a.to_dict() for a in self._alerts]

    def clear(self) -> None:
        self._alerts.clear()


alert_store = AlertStore()
