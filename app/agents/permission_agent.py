from app.services.mitre_mapper import map_flags_to_techniques

SENSITIVE_PERMISSIONS = {
    "READ_CONTACTS":          "SENSITIVE_READ_CONTACTS",
    "READ_CALL_LOG":          "SENSITIVE_READ_CONTACTS",
    "RECORD_AUDIO":           "SENSITIVE_RECORD_AUDIO",
    "ACCESS_FINE_LOCATION":   "SENSITIVE_FINE_LOCATION",
    "READ_SMS":               "SENSITIVE_READ_SMS",
    "CAMERA":                 "SENSITIVE_RECORD_AUDIO",
    "PROCESS_OUTGOING_CALLS": "SENSITIVE_READ_CONTACTS",
    "BIND_DEVICE_ADMIN":      "SENSITIVE_FINE_LOCATION",
}


class PermissionAgent:
    """Detects dangerous permission escalation sequences."""

    def can_handle(self, event: dict) -> bool:
        return event.get("type") in ("permission", "permission_request")

    async def process(self, event: dict) -> dict:
        requested = set(event.get("permissions", []))
        sensitive_hits = requested & set(SENSITIVE_PERMISSIONS)
        escalation = event.get("escalation_sequence", [])
        escalation_detected = len(escalation) > 2

        # dict.fromkeys preserves insertion order while deduplicating — multiple
        # permissions can map to the same flag string (e.g. READ_CONTACTS and
        # READ_CALL_LOG both emit SENSITIVE_READ_CONTACTS).
        flags: list[str] = list(dict.fromkeys(SENSITIVE_PERMISSIONS[p] for p in sensitive_hits))
        if escalation_detected:
            flags.append("PERMISSION_ESCALATION_DETECTED")

        risk = len(sensitive_hits) + (3 if escalation_detected else 0)

        return {
            "agent": "permission",
            "flags": flags,
            "sensitive_permissions": list(sensitive_hits),
            "escalation_detected": escalation_detected,
            "risk_score": risk,
            "mitre_techniques": map_flags_to_techniques(flags),
        }
