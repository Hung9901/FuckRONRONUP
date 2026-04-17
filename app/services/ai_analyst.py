"""
Claude Opus 4.7 — AI Threat Intelligence Engine.

Every threat chain is analyzed by Claude using:
  - Adaptive thinking for deep multi-step reasoning
  - Forced tool use for structured, schema-validated output
  - Prompt caching on the large system prompt (saves ~90% on repeated calls)
  - Graceful fallback to a rich demo report when ANTHROPIC_API_KEY is not set
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from app.core.config import settings
from app.core.logging import get_logger

if TYPE_CHECKING:
    from anthropic import AsyncAnthropic as _AsyncAnthropic

log = get_logger(__name__)

# Lazy singleton — created once when the first real analysis is requested.
# Avoids importing the anthropic package at module load time when the key
# is not set (e.g. demo / test environments).
_client: "_AsyncAnthropic | None" = None


def _get_client() -> "_AsyncAnthropic":
    global _client
    if _client is None:
        from anthropic import AsyncAnthropic
        _client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
    return _client

# ── System prompt (cached) ────────────────────────────────────────────────────
_SYSTEM = """You are an elite mobile threat intelligence analyst embedded in an enterprise security operations center.
You specialize in Android and iOS malware analysis, mobile threat hunting, and incident response.

YOUR EXPERTISE COVERS:
- Mobile malware taxonomy: banking trojans, RATs, stalkerware, spyware, adware, ransomware
- MITRE ATT&CK for Mobile framework (all tactics and techniques)
- Mobile kill-chain analysis: initial access → persistence → privilege escalation → collection → exfiltration
- Behavioral detection: accessibility abuse, permission escalation, background exfil, UI overlay attacks
- Threat actor profiling: APT groups, commodity malware operators, nation-state actors
- Regulatory compliance: GDPR, HIPAA, PCI DSS, SOX, CCPA, ISO 27001
- Mobile EDR pipeline internals: z-score anomaly detection, attack graph scoring, sequence detection

DETECTION PIPELINE SIGNALS YOU WILL ANALYZE:
- phishing_click: device clicked a suspicious URL outside expected app context
- permission_request: escalating sensitive permission requests (contacts, audio, location, SMS)
- accessibility_enabled: undeclared accessibility service with high event rate
- background_activity: boot-persistent foreground service with restart loop
- data_transfer: large-volume background exfil to unknown external host
- history anomaly: z-score spike in event rate baseline
- ui overlay: fake dialog, tapjacking, invisible touch intercept

PIPELINE SCORING:
- Risk score is additive across agents; thresholds: MEDIUM>5, HIGH>10, CRITICAL>20
- Attack graph weights nodes: EXFIL(6) > PERSISTENCE(5) > PERMISSION/ACCESSIBILITY(4) > PHISHING(3)
- Sequence detector checks for ordered: phishing → permission → accessibility → persistence → exfil
- Full chain detection signals the highest-confidence attack scenario

ANALYSIS STANDARDS:
1. Never cry wolf — assess false-positive probability honestly
2. Be specific and actionable — generic advice is useless to a SOC analyst
3. Map every behavioral observation to a MITRE technique
4. Rank recommended actions by urgency (minutes vs hours vs days)
5. Quantify business impact in terms SOC managers and CISOs understand
6. Compliance implications must cite specific articles/requirements, not just regulation names"""

# ── Structured-output tool schema ─────────────────────────────────────────────
_THREAT_REPORT_TOOL: dict = {
    "name": "threat_report",
    "description": (
        "Produce a fully structured threat intelligence report for a mobile device "
        "behavioral alert. Fill every field with specific, actionable analysis."
    ),
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "severity",
            "executive_summary",
            "attack_narrative",
            "threat_actor_profile",
            "malware_classification",
            "attack_stage",
            "recommended_actions",
            "business_impact",
            "compliance_implications",
            "ioc_indicators",
            "hunting_queries",
            "confidence_score",
            "false_positive_probability",
            "false_positive_scenarios",
            "mitre_techniques",
        ],
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "description": "Overall threat severity based on risk score and behavioral patterns.",
            },
            "executive_summary": {
                "type": "string",
                "description": (
                    "1-2 sentence non-technical summary for a CISO. State what is happening "
                    "and the immediate business risk."
                ),
            },
            "attack_narrative": {
                "type": "string",
                "description": (
                    "Technical narrative (3-5 sentences) describing the attacker's steps, "
                    "methods, and likely objectives based on the observed signal chain."
                ),
            },
            "threat_actor_profile": {
                "type": "string",
                "description": (
                    "Profile the likely threat actor: sophistication level, motivation "
                    "(financial, espionage, stalkerware), likely toolset, and whether "
                    "this matches known APT/crimeware patterns."
                ),
            },
            "malware_classification": {
                "type": "string",
                "description": (
                    "Best-fit malware family type. Examples: Banking Trojan, Remote Access "
                    "Trojan (RAT), Stalkerware, Spyware, Dropper, Adware with Surveillance."
                ),
            },
            "attack_stage": {
                "type": "string",
                "enum": [
                    "INITIAL_ACCESS",
                    "EXECUTION",
                    "PERSISTENCE",
                    "PRIVILEGE_ESCALATION",
                    "DEFENSE_EVASION",
                    "CREDENTIAL_ACCESS",
                    "DISCOVERY",
                    "COLLECTION",
                    "COMMAND_AND_CONTROL",
                    "EXFILTRATION",
                    "IMPACT",
                ],
                "description": "Most advanced kill-chain stage reached by the attacker.",
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 3,
                "description": (
                    "Prioritized response actions. Lead each with a time horizon: "
                    "[IMMEDIATE], [WITHIN 1H], [WITHIN 24H], [STRATEGIC]."
                ),
            },
            "business_impact": {
                "type": "string",
                "description": (
                    "Concrete business impact if the threat is not contained: data types "
                    "at risk, potential financial loss, reputational damage, operational disruption."
                ),
            },
            "compliance_implications": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific regulatory obligations triggered. Cite article numbers and "
                    "deadlines. Example: 'GDPR Art. 33 — 72-hour breach notification to DPA'."
                ),
            },
            "ioc_indicators": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Indicators of Compromise extracted from the behavioral data.",
            },
            "hunting_queries": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Threat hunting queries or investigation steps to find other "
                    "affected devices in the fleet."
                ),
            },
            "confidence_score": {
                "type": "number",
                "description": "0.0–1.0 confidence that this is a true positive.",
            },
            "false_positive_probability": {
                "type": "string",
                "enum": ["VERY_LOW", "LOW", "MEDIUM", "HIGH"],
                "description": "Likelihood this alert is a false positive.",
            },
            "false_positive_scenarios": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Legitimate use cases that could produce these signals.",
            },
            "mitre_techniques": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "name", "tactic"],
                    "properties": {
                        "id":     {"type": "string"},
                        "name":   {"type": "string"},
                        "tactic": {"type": "string"},
                    },
                },
                "description": "MITRE ATT&CK for Mobile techniques observed in this incident.",
            },
        },
    },
}


# ── Context formatter ──────────────────────────────────────────────────────────
def _fmt(context: dict) -> str:
    risk  = context.get("risk_snapshot", context.get("final_risk", {}))
    graph = context.get("graph", {})
    tl    = context.get("timeline", [])
    # Derive events from the timeline only when the caller did not pass them
    # explicitly. Avoids eagerly evaluating the list-comprehension default
    # (which would re-create the same data the code below uses anyway).
    events = context.get("events") or [e.get("event", e) for e in tl]

    lines: list[str] = [
        "MOBILE THREAT DETECTION — INCIDENT CONTEXT",
        "=" * 50,
        f"Device ID       : {context.get('device_id', 'unknown')}",
        f"Analysis Time   : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "── PIPELINE RISK ASSESSMENT ──",
        f"Total Risk Score   : {risk.get('total_risk', 0)}",
        f"Threat Level       : {risk.get('threat_level', 'UNKNOWN')}",
        f"Active Signals     : {', '.join(risk.get('active_signals', []) or [])}",
        f"Agent Hit Counts   : {json.dumps(risk.get('agent_hits', {}))}",
        "",
        "── SEQUENCE DETECTION ──",
        f"Ordered Chain Found     : {context.get('sequence_detected', False)}",
        f"Windowed Chain Found    : {context.get('sequence_detected_windowed', False)}",
        f"Detected Pattern        : {context.get('detected_pattern', 'N/A')}",
        "",
        "── ATTACK GRAPH SCORING ──",
        f"Graph Score        : {graph.get('graph_score', 0)}",
        f"Coverage           : {round((graph.get('coverage', 0)) * 100)}%",
        f"Matched Nodes      : {', '.join(graph.get('matched_nodes', []))}",
        f"Full Chain Detected: {graph.get('full_chain_detected', False)}",
        "",
        "── EVENT TIMELINE ──",
    ]

    for i, entry in enumerate(tl, 1):
        ev      = entry.get("event", {})
        results = entry.get("agent_results", [])
        snap    = entry.get("risk_snapshot", {})
        all_flags = []
        for r in results:
            all_flags.extend(r.get("flags", []))
        lines.append(
            f"[{i}] type={ev.get('type','?')}  "
            f"agents={[r.get('agent') for r in results]}  "
            f"flags={all_flags}  "
            f"risk_after={snap.get('total_risk', '?')}"
        )
        if ev.get("url"):
            lines.append(f"     url={ev['url']}")
        if ev.get("permissions"):
            lines.append(f"     permissions={ev['permissions']}")
        if ev.get("bytes_sent"):
            lines.append(f"     bytes_sent={ev['bytes_sent']}")

    lines += [
        "",
        "── RAW AGENT SIGNALS ──",
        json.dumps({
            "events": [e.get("event", e) for e in tl] if tl else events,
            "active_signals": risk.get("active_signals", []),
        }, default=str, indent=2)[:2000],   # cap to avoid token overflow
    ]
    return "\n".join(lines)


# ── Demo fallback (no API key) ─────────────────────────────────────────────────
_DEMO_REPORT: dict = {
    "severity": "CRITICAL",
    "executive_summary": (
        "The device has executed a complete mobile banking trojan attack chain with "
        "high confidence. Immediate device quarantine and credential revocation are required."
    ),
    "attack_narrative": (
        "The attacker gained initial access via a phishing link masquerading as a software "
        "update. After the user interaction, the malware systematically escalated permissions "
        "(contacts, audio, location) to maximize data collection capability. An undeclared "
        "accessibility service was activated to enable keylogging and screen capture, while "
        "a boot-persistent foreground service ensured survival across reboots. The campaign "
        "concluded with a 2 MB bulk exfiltration to an unknown external host in a background "
        "transfer burst — a classic banking trojan data harvest pattern."
    ),
    "threat_actor_profile": (
        "Moderately sophisticated financially-motivated threat actor, likely operating "
        "a commodity banking trojan toolkit (consistent with Anatsa, Cerberus, or SharkBot "
        "families). The ordered execution of the kill chain indicates scripted automation "
        "rather than manual operator activity, suggesting a crimeware-as-a-service model."
    ),
    "malware_classification": "Mobile Banking Trojan / Credential-Harvesting RAT",
    "attack_stage": "EXFILTRATION",
    "recommended_actions": [
        "[IMMEDIATE] Quarantine device — revoke network access and MDM enroll now",
        "[IMMEDIATE] Revoke all credentials entered on device in the past 72 hours (banking, SSO, email)",
        "[WITHIN 1H] Force remote wipe if device contains enterprise data",
        "[WITHIN 1H] Check SIEM for C2 traffic from device IP to the exfil destination",
        "[WITHIN 24H] Notify impacted users and initiate password resets for all accounts",
        "[WITHIN 24H] Submit malware sample to threat intelligence feed for IOC sharing",
        "[STRATEGIC] Deploy app-reputation scanning across the full device fleet",
    ],
    "business_impact": (
        "High risk of credential theft for banking and enterprise SSO accounts. "
        "The 2 MB exfiltration likely contains contact lists, authentication tokens, "
        "and screen-captured credentials. Potential financial fraud exposure and "
        "enterprise account compromise if SSO tokens were harvested."
    ),
    "compliance_implications": [
        "GDPR Art. 33 — Personal data breach must be reported to DPA within 72 hours",
        "GDPR Art. 34 — High-risk breach may require direct notification to affected individuals",
        "PCI DSS Req. 12.10 — Activate incident response plan; document timeline",
        "HIPAA §164.410 — If PHI on device, breach notification to HHS within 60 days",
        "SOX §302/404 — Document control failure if device had access to financial systems",
    ],
    "ioc_indicators": [
        "Suspicious URL: http://fake-update.example.com",
        "Undeclared accessibility service (event_rate=180, declared_use=false)",
        "Boot-persistent foreground service (restart_count=6)",
        "2 MB background exfiltration to unknown external host",
        "Ordered attack chain: phishing→permission→accessibility→persistence→exfil",
    ],
    "hunting_queries": [
        "Fleet scan: devices with RECORD_AUDIO + ACCESS_FINE_LOCATION granted in last 7 days",
        "Network: outbound connections >500 KB to previously-unseen external IPs in last 24h",
        "EDR: devices with boot-registered broadcast receivers not matching known-good app list",
        "Phishing feed: check fake-update.example.com across URL filtering logs fleet-wide",
    ],
    "confidence_score": 0.96,
    "false_positive_probability": "VERY_LOW",
    "false_positive_scenarios": [
        "An enterprise accessibility app (e.g. screen reader for visually impaired) — "
        "but would appear in declared_use=true and wouldn't chain with phishing/exfil",
    ],
    "mitre_techniques": [
        {"id": "T1566",    "name": "Phishing",                            "tactic": "Initial Access"},
        {"id": "T1456",    "name": "Drive-by Compromise",                 "tactic": "Initial Access"},
        {"id": "T1624.001","name": "Event Triggered Execution: Broadcast Receivers", "tactic": "Persistence"},
        {"id": "T1603",    "name": "Scheduled Task/Job",                  "tactic": "Persistence"},
        {"id": "T1541",    "name": "Foreground Persistence",              "tactic": "Persistence"},
        {"id": "T1404",    "name": "Exploitation for Privilege Escalation","tactic": "Privilege Escalation"},
        {"id": "T1629",    "name": "Impair Defenses",                     "tactic": "Defense Evasion"},
        {"id": "T1444",    "name": "Masquerade as Legitimate Application","tactic": "Defense Evasion"},
        {"id": "T1417.001","name": "Input Capture: Keylogging",           "tactic": "Collection"},
        {"id": "T1417.002","name": "Input Capture: GUI Input Capture",    "tactic": "Collection"},
        {"id": "T1513",    "name": "Screen Capture",                      "tactic": "Collection"},
        {"id": "T1432",    "name": "Access Contact List",                 "tactic": "Collection"},
        {"id": "T1429",    "name": "Capture Audio",                       "tactic": "Collection"},
        {"id": "T1430",    "name": "Location Tracking",                   "tactic": "Collection"},
        {"id": "T1437.001","name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
        {"id": "T1639",    "name": "Exfiltration Over Alternative Protocol","tactic": "Exfiltration"},
        {"id": "T1644",    "name": "Out of Band Data Exfiltration",       "tactic": "Exfiltration"},
    ],
    "_demo": True,
}


# ── Main analysis function ─────────────────────────────────────────────────────
async def analyze_threat(context: dict) -> dict:
    """
    Run Claude Opus 4.7 threat analysis on a detection context dict.

    Returns a structured threat report dict.  Falls back to a rich demo
    report if ANTHROPIC_API_KEY is not configured.
    """
    if not settings.ANTHROPIC_API_KEY:
        log.warning("ai_analyst_demo_mode", extra={"reason": "ANTHROPIC_API_KEY not set"})
        return _DEMO_REPORT

    try:
        client = _get_client()

        response = await client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=settings.AI_MAX_TOKENS,
            thinking={"type": "adaptive"},
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM,
                    "cache_control": {"type": "ephemeral"},  # cached across repeated calls
                }
            ],
            tools=[_THREAT_REPORT_TOOL],
            tool_choice={"type": "tool", "name": "threat_report"},
            messages=[{"role": "user", "content": _fmt(context)}],
        )

        for block in response.content:
            if getattr(block, "type", None) == "tool_use" and block.name == "threat_report":
                report = dict(block.input)
                log.info(
                    "ai_analysis_complete",
                    extra={
                        "severity": report.get("severity"),
                        "confidence": report.get("confidence_score"),
                        "cache_read": getattr(response.usage, "cache_read_input_tokens", 0),
                        "input_tokens": getattr(response.usage, "input_tokens", 0),
                    },
                )
                return report

        log.error("ai_analyst_no_tool_block")
        return _DEMO_REPORT

    except Exception as exc:
        log.error("ai_analyst_error", extra={"error": str(exc)})
        return {**_DEMO_REPORT, "_error": str(exc)}
