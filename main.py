import os
import re
import uuid
import time
from typing import Dict, List, Literal, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, Field



HACKATHON_API_KEY = os.getenv("HACKATHON_API_KEY")  
if not HACKATHON_API_KEY:
    print("WARNING: HACKATHON_API_KEY is not set in environment variables")

HACKATHON_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


app = FastAPI(title="Agentic Scam Honeypot", version="1.0")


def verify_api_key(x_api_key: str = Header(...)):
    if not HACKATHON_API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if x_api_key != HACKATHON_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")


sessions: Dict[str, List[Dict[str, str]]] = {}


class HumanMessage(BaseModel):
    role: Literal["user", "agent"]
    message: str

class ChatRequest(BaseModel):
    sessionId: Optional[str] = None
    message: str = Field(..., min_length=1, max_length=2000)

class ChatResponse(BaseModel):
    sessionId: str
    agentReply: str
    scamDetected: bool
    conversationHistory: List[HumanMessage]
    callbackStatus: int
    callbackTimeSeconds: float


class Intelligence:
    def __init__(self):
        self.bankAccounts = set()
        self.upiIds = set()
        self.phishingLinks = set()
        self.phoneNumbers = set()
        self.suspiciousKeywords = set()

    def extract(self, text: str):
        # Phone numbers (India style)
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


def generate_agent_reply(user_msg: str, intel: Intelligence, history: List[Dict[str, str]]) -> str:
    text = user_msg.lower()

    # Self-correction: if user contradicts or pushes for sensitive data
    if "otp" in text or "password" in text:
        return "I cannot share OTP or passwords. Please explain the legitimate purpose clearly."

    if intel.phishingLinks:
        return "This link looks unsafe. Please verify your identity through official channels."

    if intel.upiIds or intel.bankAccounts:
        return "I am not comfortable sharing financial details. Can you provide official verification?"

    # If conversation is going long, probe more
    if len(history) >= 4:
        return "Your request still seems unclear. Please provide official proof or contact details."

    return "Can you share more details about this request so I can understand it better?"



@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(verify_api_key)])
def chat(req: ChatRequest):
    # Create or load session
    if not req.sessionId:
        session_id = str(uuid.uuid4())
        sessions[session_id] = []
    else:
        session_id = req.sessionId
        if session_id not in sessions:
            sessions[session_id] = []

    
    sessions[session_id].append({"role": "user", "message": req.message})

    
    intel = Intelligence()
    for turn in sessions[session_id]:
        intel.extract(turn["message"])

    scam_detected = is_scam(intel)

    agent_reply = generate_agent_reply(req.message, intel, sessions[session_id])
    sessions[session_id].append({"role": "agent", "message": agent_reply})

   
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
        "agentNotes": "Automated agentic honeypot analysis with multi-turn context and self-correction."
    }

    
    start = time.time()
    try:
        response = requests.post(
            HACKATHON_CALLBACK_URL,
            json=payload,
            timeout=5
        )
        status_code = response.status_code
    except requests.exceptions.RequestException:
        status_code = 0
    elapsed = time.time() - start

    
    history_out = [HumanMessage(role=turn["role"], message=turn["message"]) for turn in sessions[session_id]]

    return ChatResponse(
        sessionId=session_id,
        agentReply=agent_reply,
        scamDetected=scam_detected,
        conversationHistory=history_out,
        callbackStatus=status_code,
        callbackTimeSeconds=round(elapsed, 3)
    )


@app.get("/")
def root():
    return {"status": "ok", "message": "Agentic Scam Honeypot Running"}


