"""
OpenRouter AI Service for MedTara TARA Module
=============================================
Integrates with OpenRouter-hosted LLMs to provide AI-driven threat analysis.
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

_api_key = os.getenv("OPENROUTER_API_KEY", "")
_model_name = os.getenv("OPENROUTER_MODEL", "openrouter/free")
_base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

if _api_key and _api_key != "your_real_openrouter_api_key":
    _openrouter_ready = True
else:
    _openrouter_ready = False
    print("[WARN] OPENROUTER_API_KEY is not set — AI analysis will return fallback responses.")

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
    return _openrouter_ready


def analyze_threat(event_data: dict) -> dict:
    if not _openrouter_ready:
      return _fallback_response(event_data, reason="OpenRouter API key not configured")

    user_prompt = _build_user_prompt(event_data)

    try:
        raw_text = _call_openrouter_api(user_prompt)
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
        print(f"[ERROR] OpenRouter API call failed: {exc}")
        traceback.print_exc()
        return _fallback_response(event_data, reason=str(exc))


def _call_openrouter_api(user_prompt: str) -> str:
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
            "Authorization": f"Bearer {_api_key}",
            "HTTP-Referer": "http://localhost:5001",
            "X-Title": "MedTara AI Services"
        },
        method="POST"
    )

    try:
        with request.urlopen(req, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter returned HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach OpenRouter API: {exc.reason}") from exc

    choices = payload.get("choices", [])
    if not choices:
        raise RuntimeError(f"OpenRouter response did not include choices: {payload}")

    message = choices[0].get("message", {})
    text = str(message.get("content", "")).strip()
    if not text:
        raise RuntimeError(f"OpenRouter response content was empty: {payload}")

    return text


def _build_user_prompt(event_data: dict) -> str:
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

        print(f"[WARN] Could not parse OpenRouter response as JSON: {text[:200]}")
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
            "Configure a valid OpenRouter API key to enable AI-powered analysis.",
            "Monitor the event manually until AI analysis is available.",
        ]),
        "matchedRules": rule_hints.get("matchedRules", []),
        "indicators": rule_hints.get("indicators", []),
        "aiConfidence": "low",
        "aiAttackVector": "AI-based vector analysis unavailable.",
        "aiAnalyzed": False,
    }
