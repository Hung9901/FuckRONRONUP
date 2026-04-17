"""
MITRE ATT&CK for Mobile — technique database and flag/signal mapping.

Every detected flag and attack-graph signal maps to one or more official
MITRE ATT&CK for Mobile technique IDs, giving SOC teams an industry-standard
vocabulary for threat reports and SIEM correlation.
"""

from __future__ import annotations

# ── Technique catalogue ────────────────────────────────────────────────────────
# Subset of MITRE ATT&CK for Mobile most relevant to the signals this platform
# detects.  All IDs reference https://attack.mitre.org/techniques/<ID>/
MITRE_TECHNIQUES: dict[str, dict] = {
    "T1404": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1404/",
        "description": "Adversaries exploit vulnerabilities to gain elevated privileges.",
    },
    "T1406": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1406/",
        "description": "Adversaries obfuscate malicious code to hinder detection.",
    },
    "T1411": {
        "name": "Input Prompt",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1411/",
        "description": "Adversaries display a fake prompt to capture user credentials.",
    },
    "T1412": {
        "name": "Capture SMS Messages",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1412/",
        "description": "Adversaries read SMS messages to intercept OTPs and 2FA codes.",
    },
    "T1417": {
        "name": "Input Capture",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1417/",
        "description": "Adversaries capture user input to gather credentials.",
    },
    "T1417.001": {
        "name": "Input Capture: Keylogging",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1417/001/",
        "description": "Adversaries log keystrokes via accessibility services.",
    },
    "T1417.002": {
        "name": "Input Capture: GUI Input Capture",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1417/002/",
        "description": "Adversaries capture input from GUI elements using overlay attacks.",
    },
    "T1429": {
        "name": "Capture Audio",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1429/",
        "description": "Adversaries activate the microphone to eavesdrop.",
    },
    "T1430": {
        "name": "Location Tracking",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1430/",
        "description": "Adversaries track device location to profile the victim.",
    },
    "T1432": {
        "name": "Access Contact List",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1432/",
        "description": "Adversaries exfiltrate the device contact list.",
    },
    "T1437.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1437/001/",
        "description": "Adversaries use HTTP/S to blend C2 traffic with normal web traffic.",
    },
    "T1444": {
        "name": "Masquerade as Legitimate Application",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1444/",
        "description": "Adversaries disguise malware as a trusted app.",
    },
    "T1456": {
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1456/",
        "description": "Adversaries deliver malware via malicious web pages.",
    },
    "T1513": {
        "name": "Screen Capture",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1513/",
        "description": "Adversaries capture screenshots to steal displayed information.",
    },
    "T1516": {
        "name": "Input Injection",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1516/",
        "description": "Adversaries inject fake taps/swipes to perform actions without user consent.",
    },
    "T1541": {
        "name": "Foreground Persistence",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1541/",
        "description": "Adversaries use foreground services to stay alive and avoid being killed.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "description": "Adversaries send deceptive messages to trick users into clicking malicious links.",
    },
    "T1603": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1603/",
        "description": "Adversaries schedule tasks to re-launch malware after reboot or kill.",
    },
    "T1624.001": {
        "name": "Event Triggered Execution: Broadcast Receivers",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1624/001/",
        "description": "Adversaries register broadcast receivers to auto-start on BOOT_COMPLETE.",
    },
    "T1629": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1629/",
        "description": "Adversaries disable or subvert security controls on the device.",
    },
    "T1636": {
        "name": "Protected User Data",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1636/",
        "description": "Adversaries request dangerous permissions to access protected user data.",
    },
    "T1636.003": {
        "name": "Protected User Data: Contact List",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1636/003/",
        "description": "Adversaries access the contact list via READ_CONTACTS permission.",
    },
    "T1637.001": {
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1637/001/",
        "description": "Adversaries use DGA to dynamically generate C2 domains.",
    },
    "T1639": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1639/",
        "description": "Adversaries exfiltrate data over non-standard protocols.",
    },
    "T1644": {
        "name": "Out of Band Data Exfiltration",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1644/",
        "description": "Adversaries exfiltrate data in background without user interaction.",
    },
}

# ── Agent flag → MITRE technique IDs ─────────────────────────────────────────
FLAG_TO_MITRE: dict[str, list[str]] = {
    # PhishingAgent
    "PHISHING_URL":          ["T1566", "T1456"],
    "AUTO_CLICK":            ["T1516", "T1411"],
    "OUT_OF_CONTEXT_CLICK":  ["T1566", "T1411"],
    # AccessibilityAgent
    "ACCESSIBILITY_RISK":          ["T1417", "T1513"],
    "UNDECLARED_ACCESSIBILITY_USE": ["T1629", "T1417.001"],
    "HIGH_EVENT_RATE":             ["T1417.001", "T1513"],
    # PersistenceAgent
    "BOOT_START":            ["T1624.001"],
    "RESTART_LOOP":          ["T1603"],
    "LONG_RUNNING_SERVICE":  ["T1541"],
    # PermissionAgent
    "PERMISSION_ESCALATION_DETECTED": ["T1404", "T1636"],
    "SENSITIVE_READ_CONTACTS":         ["T1636.003", "T1432"],
    "SENSITIVE_RECORD_AUDIO":          ["T1429"],
    "SENSITIVE_FINE_LOCATION":         ["T1430"],
    "SENSITIVE_READ_SMS":              ["T1412"],
    # ExfilAgent
    "LARGE_PAYLOAD":         ["T1639", "T1644"],
    "UNKNOWN_EXTERNAL_HOST": ["T1437.001", "T1637.001"],
    "BACKGROUND_TRANSFER":   ["T1644"],
    "TRANSFER_BURST":        ["T1639"],
    # AnomalyAgent
    "ANOMALY_DETECTED":      ["T1417", "T1429"],
    # UIAgent
    "OVERLAY_ATTACK":        ["T1417.002", "T1516"],
    "FAKE_DIALOG":           ["T1444", "T1411"],
    "TAPJACKING":            ["T1516", "T1417.002"],
    "INVISIBLE_INTERCEPT":   ["T1516"],
}

# ── Attack-graph signal → MITRE technique IDs ─────────────────────────────────
SIGNAL_TO_MITRE: dict[str, list[str]] = {
    "PHISHING_INTERACTION":  ["T1566", "T1456"],
    "PERMISSION_ESCALATION": ["T1404", "T1636"],
    "ACCESSIBILITY_RISK":    ["T1417", "T1417.001", "T1513", "T1629"],
    "PERSISTENCE_PATTERN":   ["T1603", "T1624.001", "T1541"],
    "EXFIL_PATTERN":         ["T1639", "T1644", "T1437.001"],
    "UI_ATTACK":             ["T1516", "T1444", "T1417.002"],
}

# ── Ordered tactic display ─────────────────────────────────────────────────────
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def get_technique(technique_id: str) -> dict | None:
    return MITRE_TECHNIQUES.get(technique_id)


def _collect(ids: list[str], seen: set[str], result: list[dict]) -> None:
    for tid in ids:
        if tid not in seen and tid in MITRE_TECHNIQUES:
            seen.add(tid)
            result.append({"id": tid, **MITRE_TECHNIQUES[tid]})


def map_flags_to_techniques(flags: list[str]) -> list[dict]:
    """Return de-duplicated MITRE technique dicts for a list of agent flags."""
    seen: set[str] = set()
    result: list[dict] = []
    for flag in flags:
        _collect(FLAG_TO_MITRE.get(flag, []), seen, result)
    return result


def map_signals_to_techniques(signals: set[str] | list[str]) -> list[dict]:
    """Return de-duplicated MITRE technique dicts for attack-graph signals."""
    seen: set[str] = set()
    result: list[dict] = []
    for signal in signals:
        _collect(SIGNAL_TO_MITRE.get(signal, []), seen, result)
    return result


def all_techniques_from_context(
    flags: list[str],
    signals: set[str] | list[str] | None = None,
) -> list[dict]:
    """Combine flags + signals into one de-duplicated, tactic-sorted list."""
    seen: set[str] = set()
    result: list[dict] = []
    for flag in flags:
        _collect(FLAG_TO_MITRE.get(flag, []), seen, result)
    for signal in signals or []:
        _collect(SIGNAL_TO_MITRE.get(signal, []), seen, result)
    return sorted(result, key=lambda t: (TACTIC_ORDER.index(t["tactic"])
                                         if t["tactic"] in TACTIC_ORDER else 99, t["id"]))


def techniques_by_tactic(techniques: list[dict]) -> dict[str, list[dict]]:
    """Group a technique list by tactic for display."""
    out: dict[str, list[dict]] = {}
    for t in techniques:
        out.setdefault(t["tactic"], []).append(t)
    return out
