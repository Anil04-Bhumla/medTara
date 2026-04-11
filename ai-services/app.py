"""
MedTara AI Services — Flask Application
========================================
REST API that bridges the Node.js backend with xAI Grok
for AI-driven threat analysis and risk assessment.

Endpoints:
  GET  /api/health       — Service health check
  POST /api/analyze      — Analyze a threat event with Grok AI
"""

import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

from services.grok_service import analyze_threat, is_ready

AI_SERVICES_ROOT = Path(__file__).resolve().parent
load_dotenv(AI_SERVICES_ROOT / ".env")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app, origins=["http://localhost:8000", "http://127.0.0.1:8000",
                    "http://localhost:5173", "http://127.0.0.1:5173"])

PORT = int(os.getenv("FLASK_PORT", 5001))
DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/api/health", methods=["GET"])
def health_check():
    """Return service status and Grok readiness."""
    return jsonify({
        "status": "ok",
        "service": "MedTara AI Services",
        "provider": "xai-grok",
        "grokReady": is_ready(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze a threat event using xAI Grok.

    Expected JSON body:
    {
        "eventType": "string",
        "input": "string",
        "payload": "string",
        "metadata": {},
        "ruleBasedHints": {}
    }
    """
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    event_type = data.get("eventType")
    if not event_type:
        return jsonify({"error": "eventType is required"}), 400

    try:
        result = analyze_threat(data)
        return jsonify({
            "success": True,
            "analysis": result,
            "analyzedAt": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        print(f"[ERROR] Analysis failed: {exc}")
        return jsonify({
            "success": False,
            "error": str(exc),
            "analysis": {
                "summary": "AI analysis failed due to an internal error.",
                "attackType": "Suspicious Activity",
                "severity": "medium",
                "riskScore": 50,
                "impact": "Unable to assess impact.",
                "mitigation": ["Retry the analysis or check AI service logs."],
                "matchedRules": [],
                "indicators": [],
                "aiConfidence": "low",
                "aiAttackVector": "Unknown",
                "aiAnalyzed": False,
            }
        }), 500


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  MedTara AI Services")
    print(f"  Port: {PORT}")
    print(f"  Grok Ready: {is_ready()}")
    print(f"{'='*60}\n")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
