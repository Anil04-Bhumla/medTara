# MedTara AI Services

Python-based AI microservice that integrates **OpenRouter-hosted LLMs** into the MedTara Threat Analysis and Risk Assessment (TARA) module as the primary assessment engine.

## Setup

### 1. Install Dependencies

```bash
cd ai-services
pip install -r requirements.txt
```

### 2. Configure OpenRouter API Key

Get an API key from OpenRouter.

Edit `ai-services/.env`:

```env
OPENROUTER_API_KEY=your-actual-openrouter-api-key-here
OPENROUTER_MODEL=openrouter/free
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

### 3. Run the Service

```bash
python app.py
```

The service starts on `http://localhost:5001`.

## API Endpoints

### `GET /api/health`

Returns service status and OpenRouter readiness.

```json
{
  "status": "ok",
  "service": "MedTara AI Services",
  "provider": "openrouter",
  "openrouterReady": true,
  "timestamp": "2025-01-01T00:00:00Z"
}
```

### `POST /api/analyze`

Analyzes a security event using OpenRouter and returns the main TARA assessment.

**Request Body:**

```json
{
  "eventType": "Manual Threat Check",
  "input": "' OR 1=1 --",
  "payload": "",
  "metadata": {},
  "ruleBasedHints": {
    "attackType": "Potential SQL Injection",
    "severity": "critical",
    "riskScore": 85
  }
}
```

**Response:**

```json
{
  "success": true,
  "analysis": {
    "summary": "This input contains a classic SQL injection attempt...",
    "attackType": "Potential SQL Injection",
    "severity": "critical",
    "riskScore": 91,
    "impact": "If successful, the attacker could expose protected patient records...",
    "mitigation": ["Use parameterized queries...", "..."],
    "matchedRules": ["OWASP-A03-Injection"],
    "indicators": ["SQL keywords detected in user input"],
    "aiConfidence": "high",
    "aiAttackVector": "Classic tautology-based SQL injection...",
    "aiAnalyzed": true
  },
  "analyzedAt": "2025-01-01T00:00:00Z"
}
```

## Architecture

```
Node.js Backend (port 8000)
    ↓  POST /api/analyze
Python AI Service (port 5001)
    ↓  OpenRouter API call
OpenRouter free model
    ↓  Structured JSON response
Python AI Service
    ↓  Returns primary AI assessment
Node.js Backend
    ↓  Persists AI-driven TARA result (with baseline fallback if needed)
React Frontend (port 5173)
```
