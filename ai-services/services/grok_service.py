"""
Grok AI Service for MedTara TARA Module
=======================================
Integrates with xAI Grok to provide AI-driven threat analysis.
Accepts structured threat context from the Node.js backend and returns
primary AI-generated security assessments.
"""

import json
import os
import traceback
from pathlib import Path
from urllib import error, request

from dotenv import load_dotenv

AI_SERVICES_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(AI_SERVICES_ROOT / ".env")

# ---------------------------------------------------------------------------
# Grok / xAI configuration
# ---------------------------------------------------------------------------

_api_key = os.getenv("XAI_API_KEY", "") or os.getenv("GROK_API_KEY", "")
_model_name = (
    os.getenv("XAI_MODEL", "")
    or os.getenv("GROK_MODEL", "")
    or "grok-4.20-beta-latest-non-reasoning"
)
_base_url = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1")

if _api_key and _api_key != "your-xai-api-key-here":
    _grok_ready = True
else:
    _grok_ready = False
    print("[WARN] XAI_API_KEY is not set — AI analysis will return fallback responses.")

# ---------------------------------------------------------------------------
# System prompt — instructs Grok to behave as a cybersecurity expert
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specializing in healthcare data protection
and threat analysis. You are the primary assessment engine for an AI-driven Threat Analysis and
Risk Assessment (TARA) module inside a secure healthcare platform called MedTara.

Your job is to review the raw security event and produce the platform's main threat assessment.
Rule-based hints may be provided as supporting context, but you must make your own judgment based
on the event details. The platform protects patient records, diagnostic reports, and other
healthcare data.

You must respond with a JSON object containing exactly these fields:

{
  "summary": "A concise 2-3 sentence primary assessment of the event.",
  "attackType": "Short threat label such as Potential SQL Injection, Potential XSS, Benign Activity, etc.",
  "severity": "low | medium | high | critical",
  "riskScore": 0,
  "impact": "Healthcare-specific impact of the event.",
  "mitigation": ["3-5 concrete mitigation steps tailored to this exact event."],
  "matchedRules": ["Relevant OWASP or custom detection labels, if any."],
  "indicators": ["Observed indicators or suspicious traits from the event."],
  "aiConfidence": "high | medium | low",
  "aiAttackVector": "Short technical description of the likely attack path."
}

IMPORTANT RULES:
- Respond ONLY with the JSON object. No markdown fences, no extra commentary.
- Use the raw event as the primary source of truth. Rule-based hints are advisory, not mandatory.
- Focus on healthcare-specific risk such as patient data exposure, operational disruption,
  compliance impact, and data integrity.
- If the event looks benign, set attackType to "Benign Activity", severity to "low",
  riskScore to a low number, and aiConfidence to "low".
- Keep riskScore as an integer from 0 to 100.
"""


def is_ready() -> bool:
    """Check if the Grok service is properly configured and ready."""
    return _grok_ready


def analyze_threat(event_data: dict) -> dict:
    """
    Send a threat event to Grok for AI analysis.

    Parameters
    ----------
    event_data : dict
        May contain:
        - eventType: str
        - input: str
        - payload: str
        - metadata: object
        - ruleBasedHints: dict

    Returns
    -------
    dict with primary assessment keys plus AI metadata
    """
    if not _grok_ready:
        return _fallback_response(event_data, reason="xAI API key not configured")

    user_prompt = _build_user_prompt(event_data)

    try:
        raw_text = _call_grok_api(user_prompt)
        parsed = _parse_json_response(raw_text)

        return {
            "summary": parsed.get("summary", "AI analysis completed."),
            "attackType": parsed.get("attackType", "Suspicious Activity"),
            "severity": parsed.get("severity", "medium"),
            "riskScore": parsed.get("riskScore", 50),
            "impact": parsed.get("impact", "Impact assessment unavailable."),
            "mitigation": parsed.get("mitigation", []),
            "matchedRules": parsed.get("matchedRules", []),
            "indicators": parsed.get("indicators", []),
            "aiConfidence": parsed.get("aiConfidence", "medium"),
            "aiAttackVector": parsed.get("aiAttackVector", "Unknown vector"),
            "aiAnalyzed": True,
        }

    except Exception as exc:
        print(f"[ERROR] Grok API call failed: {exc}")
        traceback.print_exc()
        return _fallback_response(event_data, reason=str(exc))


def _call_grok_api(user_prompt: str) -> str:
    """Call the xAI chat completions endpoint and return the raw model text."""
    body = json.dumps({
        "model": _model_name,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
    }).encode("utf-8")

    req = request.Request(
        f"{_base_url}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_api_key}"
        },
        method="POST"
    )

    try:
        with request.urlopen(req, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"xAI returned HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach xAI API: {exc.reason}") from exc

    choices = payload.get("choices", [])
    if not choices:
        raise RuntimeError(f"xAI response did not include choices: {payload}")

    message = choices[0].get("message", {})
    content = message.get("content", "")

    if isinstance(content, list):
        text_parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(item.get("text", ""))
        content = "\n".join(part for part in text_parts if part)

    text = str(content).strip()
    if not text:
        raise RuntimeError(f"xAI response content was empty: {payload}")

    return text


def _build_user_prompt(event_data: dict) -> str:
    """Construct the analysis prompt from the event data."""
    event_type = event_data.get("eventType", "Unknown Event")
    raw_input = event_data.get("input", "")
    raw_payload = event_data.get("payload", "")
    metadata = event_data.get("metadata", {})
    rule_hints = event_data.get("ruleBasedHints", {}) or {}

    prompt_parts = [
        "SECURITY EVENT ANALYSIS REQUEST",
        "================================",
        "",
        f"Event Type: {event_type}",
        "",
        "Raw Input:",
        f"{raw_input[:2000] if raw_input else '(none)'}",
        "",
        "Raw Payload:",
        f"{raw_payload[:2000] if raw_payload else '(none)'}",
        "",
        "Metadata:",
        json.dumps(metadata, indent=2)[:3000] if metadata else "(none)",
        "",
        "Rule-Based Hints (supporting context only):",
        json.dumps(rule_hints, indent=2)[:3000] if rule_hints else "(none)",
        "",
        "Analyze this event as the primary TARA engine for a healthcare platform. Return the final JSON assessment only."
    ]

    return "\n".join(prompt_parts)


def _parse_json_response(raw_text: str) -> dict:
    """Parse JSON from Grok response, handling markdown fences if present."""
    text = raw_text.strip()

    if text.startswith("```"):
        lines = text.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        print(f"[WARN] Could not parse Grok response as JSON: {text[:200]}")
        return {
            "summary": text[:500] if text else "AI analysis returned an unparseable result.",
            "attackType": "Suspicious Activity",
            "severity": "medium",
            "riskScore": 50,
            "impact": "Unable to parse structured impact assessment.",
            "mitigation": ["Review the raw AI output for manual interpretation."],
            "matchedRules": [],
            "indicators": [],
            "aiConfidence": "low",
            "aiAttackVector": "Unable to determine from AI response.",
        }


def _fallback_response(event_data: dict, reason: str = "AI service unavailable") -> dict:
    """Return a structured fallback when Grok is unavailable."""
    rule_hints = event_data.get("ruleBasedHints", {}) or {}
    attack_type = rule_hints.get("attackType", "Unknown")
    return {
        "summary": f"AI analysis unavailable ({reason}). Falling back to the platform's baseline classification: {attack_type}.",
        "attackType": attack_type,
        "severity": rule_hints.get("severity", "low"),
        "riskScore": rule_hints.get("riskScore", 10),
        "impact": rule_hints.get(
            "impact",
            "AI impact assessment is unavailable. Refer to baseline findings."
        ),
        "mitigation": rule_hints.get("mitigation", [
            "Review the baseline assessment for immediate guidance.",
            "Configure a valid xAI API key to enable AI-powered analysis.",
            "Monitor the event manually until AI analysis is available.",
        ]),
        "matchedRules": rule_hints.get("matchedRules", []),
        "indicators": rule_hints.get("indicators", []),
        "aiConfidence": "low",
        "aiAttackVector": "AI-based vector analysis unavailable.",
        "aiAnalyzed": False,
    }
