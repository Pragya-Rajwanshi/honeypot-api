import os
import re
import uuid
from typing import Dict, List

import requests
from fastapi import FastAPI, Header, HTTPException, Depends, Request

# ------------------ CONFIG ------------------

HACKATHON_API_KEY = os.getenv("HACKATHON_API_KEY")
if not HACKATHON_API_KEY:
    print("WARNING: HACKATHON_API_KEY is not set in environment variables")

HACKATHON_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


app = FastAPI(title="Agentic Scam Honeypot", version="1.0")

# ------------------ AUTH ------------------

def verify_api_key(x_api_key: str = Header(None)):
    if not HACKATHON_API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API Key")
    if x_api_key != HACKATHON_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# ------------------ STORAGE ------------------

sessions: Dict[str, List[Dict[str, str]]] = {}



# ------------------ INTELLIGENCE ------------------

class Intelligence:
    def __init__(self):
        self.bankAccounts = set()
        self.upiIds = set()
        self.phishingLinks = set()
        self.phoneNumbers = set()
        self.suspiciousKeywords = set()

    def extract(self, text: str):
        # Phone numbers (India)
        for p in re.findall(r"\b[6-9]\d{9}\b", text):
            self.phoneNumbers.add(p)

        # UPI IDs
        for u in re.findall(r"\b[\w.\-]+@[\w]+\b", text):
            self.upiIds.add(u)

        # URLs
        for l in re.findall(r"https?://[^\s]+", text):
            self.phishingLinks.add(l)

        # Bank account numbers (8–18 digits)
        for a in re.findall(r"\b\d{8,18}\b", text):
            self.bankAccounts.add(a)

        # Suspicious keywords
        keywords = ["otp", "urgent", "verify", "password", "click", "refund", "prize", "lottery", "bank", "kyc"]
        for k in keywords:
            if k.lower() in text.lower():
                self.suspiciousKeywords.add(k)


def is_scam(intel: Intelligence) -> bool:
    score = 0
    if intel.phishingLinks:
        score += 2
    if intel.upiIds or intel.bankAccounts:
        score += 2
    if intel.phoneNumbers:
        score += 1
    if len(intel.suspiciousKeywords) >= 2:
        score += 2
    return score >= 3

# ------------------ API ------------------

@app.post("/chat", dependencies=[Depends(verify_api_key)])
async def chat(request: Request):
    # Safely read JSON (even if GUVI sends empty or different body)
    try:
        body = await request.json()
    except:
        body = {}

    session_id = body.get("sessionId") or str(uuid.uuid4())

    if session_id not in sessions:
        sessions[session_id] = []

    # Safely extract message text
    text = ""
    try:
        text = body.get("message", {}).get("text", "")
    except:
        text = ""

    if text:
        sessions[session_id].append({"role": "user", "message": text})

    # Extract intelligence
    intel = Intelligence()
    for turn in sessions[session_id]:
        intel.extract(turn["message"])

    scam_detected = is_scam(intel)

    # GUVI-required reply
    agent_reply = "Why is my account being suspended?"

    sessions[session_id].append({"role": "agent", "message": agent_reply})

    # Prepare callback payload
    intelligence_dict = {
        "bankAccounts": list(intel.bankAccounts),
        "upiIds": list(intel.upiIds),
        "phishingLinks": list(intel.phishingLinks),
        "phoneNumbers": list(intel.phoneNumbers),
        "suspiciousKeywords": list(intel.suspiciousKeywords),
    }

    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": len(sessions[session_id]),
        "extractedIntelligence": intelligence_dict,
        "agentNotes": "Automated agentic honeypot analysis"
    }

    # Send callback (best effort)
    try:
        requests.post(HACKATHON_CALLBACK_URL, json=payload, timeout=5)
    except requests.exceptions.RequestException:
        pass

    # ✅ EXACT RESPONSE FORMAT GUVI EXPECTS
    return {
        "status": "success",
        "reply": agent_reply
    }

# ------------------ HEALTH ------------------

@app.get("/")
def root():

    return {"status": "ok", "message": "Agentic Scam Honeypot Running"}



