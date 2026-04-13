SENSITIVE_PERMISSIONS = {
    "READ_CONTACTS", "READ_CALL_LOG", "RECORD_AUDIO",
    "ACCESS_FINE_LOCATION", "READ_SMS", "CAMERA",
    "PROCESS_OUTGOING_CALLS", "BIND_DEVICE_ADMIN",
}

class PermissionAgent:
    def can_handle(self, event):
        return event.get("type") in ("permission", "permission_request")

    async def process(self, event):
        requested = set(event.get("permissions", []))
        sensitive_hits = requested & SENSITIVE_PERMISSIONS
        escalation = event.get("escalation_sequence", [])

        risk = len(sensitive_hits) + (3 if len(escalation) > 2 else 0)

        return {
            "agent": "permission",
            "sensitive_permissions": list(sensitive_hits),
            "escalation_detected": len(escalation) > 2,
            "risk_score": risk,
        }
