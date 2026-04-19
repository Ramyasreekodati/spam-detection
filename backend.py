import os
import time
import requests
import json
import re
import google.generativeai as genai
from fastapi import FastAPI, Depends, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

import logging

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecurityBackend")

load_dotenv()

app = FastAPI(title="Agentic Honey-Pot API")

# Configuration
API_KEY = os.getenv("API_KEY")
if not API_KEY or API_KEY == "YOUR_SECRET_API_KEY":
    logger.critical("❌ SECURITY ERROR: API_KEY is missing or using insecure default. Check your .env file.")
    # In production, you would exit(1) here.
else:
    # Debug log (Masked)
    masked_key = f"{API_KEY[:4]}...{API_KEY[-4:]}" if len(API_KEY) > 8 else "****"
    logger.info(f"🛡️ Security Engine Loaded with API_KEY: {masked_key}")

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Configure Gemini
GENAI_API_KEY = os.getenv("GEMINI_API_KEY")
try:
    if GENAI_API_KEY:
        genai.configure(api_key=GENAI_API_KEY)
        # Using a more stable model name as default
        model = genai.GenerativeModel('gemini-1.5-flash')
    else:
        model = None
        print("Warning: GEMINI_API_KEY not found in .env")
except Exception as e:
    print(f"Error initializing Gemini: {e}")
    model = None

# --- Fallback Engine ---
class FallbackEngine:
    SUSPICIOUS_KEYWORDS = [
        r"lottery", r"won", r"million", r"dollars", r"claim", r"prize", r"winner", 
        r"bank details", r"account number", r"password", r"otp", r"verify", r"urgent",
        r"blocked", r"suspended", r"login", r"click here", r"gift card", r"btc", r"crypto"
    ]
    SAFE_KEYWORDS = [
        r"unsubscribe", r"view in browser", r"newsletter", r"privacy policy", r"copyright", 
        r"sent by", r"preferences", r"no longer want to receive"
    ]
    
    @staticmethod
    def analyze(text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        findings = {
            "suspiciousKeywords": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": []
        }
        
        # 1. Keywords
        for kw in FallbackEngine.SUSPICIOUS_KEYWORDS:
            if re.search(kw, text_lower):
                findings["suspiciousKeywords"].append(kw)
        
        # 2. Links
        findings["phishingLinks"] = re.findall(r'https?://\S+', text)
        
        # 3. Phone Numbers
        findings["phoneNumbers"] = re.findall(r'\+?\d{10,12}', text)
        
        # 4. Bank/UPI
        findings["upiIds"] = re.findall(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', text)
        findings["bankAccounts"] = re.findall(r'\b\d{9,18}\b', text)
        
        # Calculate Risk
        score = 0
        score += len(findings["suspiciousKeywords"]) * 8
        score += len(findings["phishingLinks"]) * 25
        score += len(findings["phoneNumbers"]) * 10
        score += len(findings["upiIds"]) * 40
        score += len(findings["bankAccounts"]) * 20
        
        # Newsletter Penalty (Reduce score if newsletter markers found)
        for skw in FallbackEngine.SAFE_KEYWORDS:
            if re.search(skw, text_lower):
                score -= 20
                break
        
        risk_score = max(0, min(score, 100))
        
        if risk_score > 85: level = "HIGH"
        elif risk_score > 50: level = "MEDIUM"
        elif risk_score > 15: level = "LOW"
        else: level = "SAFE"
        
        return {
            "scamDetected": risk_score > 30,
            "threatLevel": level,
            "riskScore": risk_score,
            "confidence": 0.6,
            "agentNotes": "Backup analysis active.",
            "agentResponse": "The AI is currently busy, so I've run a security scan using my local rules.",
            "xaiExplanations": [f"Found {len(findings['suspiciousKeywords'])} triggers" if findings['suspiciousKeywords'] else "No clear patterns found."],
            "agentReports": [{"agent_name": "Fallback", "finding": "Rule-based scan complete", "risk_contribution": risk_score}],
            "source": "FALLBACK",
            **findings
        }

# --- Pydantic Models ---
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class WebhookRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []

class WebhookResponse(BaseModel):
    status: str
    scamDetected: bool
    threatLevel: str
    riskScore: int
    confidence: float
    agentResponse: Optional[str] = None
    agentReports: List[Dict[str, Any]] = []
    xaiExplanations: List[str] = []
    extractedIntelligence: Dict[str, Any]
    agentNotes: str
    source: str = "AI"

def validate_ai_response(data: Any) -> bool:
    """Strictly validates the structure of the AI response."""
    if not isinstance(data, dict): return False
    required = ["scamDetected", "threatLevel", "riskScore", "confidence", "agentNotes"]
    return all(k in data for k in required)

# --- Logic ---
def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY: raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key

def clean_json_response(raw_text):
    try:
        json_match = re.search(r'(\{.*\})', raw_text, re.DOTALL)
        if json_match: return json.loads(re.sub(r',\s*\}', '}', re.sub(r',\s*\]', ']', json_match.group(1))))
        return json.loads(raw_text)
    except: return None

async def analyze_with_ai(text: str, history: str, retries: int = 2):
    if not model: 
        logger.warning("AI Model not initialized. Using Fallback.")
        return FallbackEngine.analyze(text)
    
    # Enforce backend text limit
    safe_text = text[:3000]
    
    prompt = f"""
    ROLE: You are a Senior Cybersecurity Forensic Agent with high accuracy requirements.
    TASK: Analyze the email for malicious intent (scams, phishing, identity theft).
    
    ACCURACY GUIDELINES (STRICT):
    1. INTENT OVER KEYWORDS: Do not flag emails as HIGH risk just because they contain "login" or "verify". These are standard in 99% of legitimate emails.
    2. SAFE BY DEFAULT: Newsletters (Substack, Medium, etc.) and legitimate account notifications (Google, Claude, Microsoft) are SAFE (Risk < 10) unless they contain a specific request for an OTP, password, or financial credentials.
    3. HIGH RISK CRITERIA: Only assign HIGH risk (>85) for definitive malicious intent:
       - Direct request for bank accounts, PAN, Aadhaar, or OTP.
       - Hidden/Masked suspicious URLs trying to steal login credentials.
       - Lottery/Gift card scams.
    4. IF INFORMATIONAL/NEWSLETTER: scamDetected MUST be false.
    5. REASONING: Explain WHY the email is safe or dangerous based on INTENT, not just keyword presence.
    5. RETURN ONLY VALID JSON.
    
    CONTEXT: {history}
    EMAIL CONTENT: {safe_text}
    
    OUTPUT FORMAT (JSON ONLY):
    {{
        "scamDetected": bool,
        "threatLevel": "HIGH" | "MEDIUM" | "LOW" | "SAFE",
        "riskScore": 0-100,
        "confidence": 0.0-1.0,
        "agentResponse": "Helpful persona-driven response",
        "agentNotes": "Technical reasoning focusing on INTENT",
        "xaiExplanations": ["Reason 1", "Reason 2"],
        "agentReports": [{{"agent_name": "Forensic", "finding": "...", "risk_contribution": int}}],
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    }}
    """
    
    import asyncio
    for attempt in range(retries + 1):
        try:
            # Use asyncio.wait_for to enforce a timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(model.generate_content, prompt),
                timeout=25.0
            )
            data = clean_json_response(response.text)
            if data and validate_ai_response(data):
                data["source"] = "AI"
                return data
            logger.warning(f"AI response failed validation on attempt {attempt+1}")
        except asyncio.TimeoutError:
            logger.error(f"AI Call Timed Out on attempt {attempt+1}")
        except Exception as e:
            logger.error(f"AI Attempt {attempt+1} failed: {e}")
            if attempt < retries: await asyncio.sleep(1)
            
    logger.error("AI failed all attempts. Triggering Fallback Engine...")
    return FallbackEngine.analyze(text)

@app.post("/webhook", response_model=WebhookResponse)
async def handle_webhook(req: WebhookRequest, api_key: str = Depends(verify_api_key)):
    logger.info(f"Processing webhook for session: {req.sessionId}")
    history = "\n".join([f"{m.sender}: {m.text}" for m in req.conversationHistory])
    ai_result = await analyze_with_ai(req.message.text, history)
    
    intel = {
        "bankAccounts": ai_result.get("bankAccounts", []),
        "upiIds": ai_result.get("upiIds", []),
        "phishingLinks": ai_result.get("phishingLinks", []),
        "phoneNumbers": ai_result.get("phoneNumbers", []),
        "suspiciousKeywords": ai_result.get("suspiciousKeywords", [])
    }
    
    return WebhookResponse(
        status="success",
        scamDetected=ai_result.get("scamDetected", False),
        threatLevel=ai_result.get("threatLevel", "SAFE"),
        riskScore=ai_result.get("riskScore", 0),
        confidence=ai_result.get("confidence", 0.0),
        agentResponse=ai_result.get("agentResponse"),
        agentReports=ai_result.get("agentReports", []),
        xaiExplanations=ai_result.get("xaiExplanations", []),
        extractedIntelligence=intel,
        agentNotes=ai_result.get("agentNotes", "Complete"),
        source=ai_result.get("source", "AI")
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
