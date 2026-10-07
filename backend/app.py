import os
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from openai import OpenAI

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "change-me")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-5-mini")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(
    title="Cyber Eye AI",
    version="1.0.0",
    description="AI-powered cybersecurity monitoring and threat detection platform."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For a student demo. Restrict to your Vercel URL later.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityEvent(BaseModel):
    device_id: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    source_ip: str = Field(min_length=1, max_length=100)
    failed_attempts: int = Field(default=0, ge=0, le=10000)
    message: str = Field(default="", max_length=2000)
    latitude: Optional[float] = None
    longitude: Optional[float] = None

def db():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    try:
        yield conn
    finally:
        conn.close()

def require_agent_key(x_agent_key: Optional[str] = Header(default=None)):
    if not x_agent_key or x_agent_key != AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid agent API key")

def rule_analysis(event: SecurityEvent):
    attempts = event.failed_attempts
    text = (event.message or "").lower()
    etype = event.event_type.lower()

    if attempts >= 10 or "brute" in etype:
        return {
            "threat": "BRUTE FORCE ATTACK",
            "severity": "CRITICAL",
            "risk_score": 95,
            "confidence": 96,
            "explanation": "Repeated authentication failures indicate likely credential brute-force activity.",
            "recommendation": "Temporarily rate-limit the source and investigate the affected account/device."
        }
    if attempts >= 5:
        return {
            "threat": "POSSIBLE BRUTE FORCE",
            "severity": "HIGH",
            "risk_score": 78,
            "confidence": 91,
            "explanation": "A high number of failed authentication attempts was observed in a short period.",
            "recommendation": "Enable rate limiting and review authentication logs."
        }
    if attempts >= 3 or "scan" in etype or "suspicious" in text:
        return {
            "threat": "SUSPICIOUS ACTIVITY",
            "severity": "MEDIUM",
            "risk_score": 55,
            "confidence": 86,
            "explanation": "The event differs from normal activity and should be investigated.",
            "recommendation": "Review the source, recent events and affected device."
        }
    return {
        "threat": "NORMAL ACTIVITY",
        "severity": "LOW",
        "risk_score": 10,
        "confidence": 80,
        "explanation": "No strong indicators of malicious activity were found.",
        "recommendation": "Continue monitoring."
    }

def ai_analysis(event: SecurityEvent):
    fallback = rule_analysis(event)
    if not OPENAI_API_KEY:
        return fallback

    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        prompt = f"""
You are a defensive cybersecurity analyst. Analyze ONLY this security event.
Do not provide offensive instructions.

Device: {event.device_id}
Event type: {event.event_type}
Source IP: {event.source_ip}
Failed attempts: {event.failed_attempts}
Message: {event.message}

Return valid JSON with exactly:
threat, severity, risk_score, confidence, explanation, recommendation

severity must be LOW, MEDIUM, HIGH, or CRITICAL.
risk_score and confidence must be integers 0-100.
Keep explanation and recommendation under 300 characters each.
"""
        response = client.responses.create(
            model=AI_MODEL,
            input=prompt
        )
        raw = response.output_text.strip()
        data = json.loads(raw)
        data["risk_score"] = max(0, min(100, int(data["risk_score"])))
        data["confidence"] = max(0, min(100, int(data["confidence"])))
        return data
    except Exception:
        # Keep the live demo working if the AI provider is unavailable.
        return fallback

@app.get("/")
def home():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/health")
def health():
    return {"status": "online", "service": "cyber-eye-ai"}

@app.get("/api/events/recent")
def recent_events(conn=Depends(db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, device_id, event_type, source_ip, failed_attempts,
                   message, threat, risk_score, severity, confidence,
                   explanation, recommendation, created_at
            FROM security_events
            ORDER BY created_at DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
    return rows

@app.get("/api/stats")
def stats(conn=Depends(db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE severity='HIGH') AS high,
                COUNT(*) FILTER (WHERE severity='MEDIUM') AS medium,
                COUNT(*) FILTER (WHERE severity='LOW') AS low
            FROM security_events
        """)
        counts = cur.fetchone()

        cur.execute("""
            SELECT COUNT(DISTINCT device_id) AS devices
            FROM security_events
        """)
        devices = cur.fetchone()

    return {
        "total_events": int(counts["total"] or 0),
        "critical": int(counts["critical"] or 0),
        "high": int(counts["high"] or 0),
        "medium": int(counts["medium"] or 0),
        "low": int(counts["low"] or 0),
        "devices": int(devices["devices"] or 0)
    }

@app.post("/api/events", dependencies=[Depends(require_agent_key)])
def receive_event(event: SecurityEvent, conn=Depends(db)):
    analysis = ai_analysis(event)

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO security_events
            (device_id, event_type, source_ip, failed_attempts, message,
             threat, risk_score, severity, confidence, explanation, recommendation,
             latitude, longitude)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id, created_at
        """, (
            event.device_id, event.event_type, event.source_ip,
            event.failed_attempts, event.message,
            analysis["threat"], analysis["risk_score"], analysis["severity"],
            analysis["confidence"], analysis["explanation"],
            analysis["recommendation"], event.latitude, event.longitude
        ))
        saved = cur.fetchone()
        conn.commit()

    return {
        "success": True,
        "event_id": saved["id"],
        "created_at": saved["created_at"],
        **analysis
    }
