import os
import logging
from fastapi import FastAPI, Depends, HTTPException, Header
from dotenv import load_dotenv

from src.backend.models.schema import WebhookRequest, WebhookResponse
from src.backend.services.ai_service import AIService

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecurityBackend")

load_dotenv()

app = FastAPI(title="Agentic Honey-Pot API - Modular Version")

# Initialize Services
ai_service = AIService()
API_KEY = os.getenv("API_KEY")

@app.get("/")
async def health_check():
    return {"status": "online", "message": "Security Backend is running"}

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key

@app.post("/webhook", response_model=WebhookResponse)
async def handle_webhook(req: WebhookRequest, api_key: str = Depends(verify_api_key)):
    logger.info(f"Processing webhook for session: {req.sessionId}")
    
    history = "\n".join([f"{m.sender}: {m.text}" for m in req.conversationHistory])
    ai_result = await ai_service.analyze(req.message.text, history)
    
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
        agentNotes=ai_result.get("agentNotes", "Analysis Complete"),
        source=ai_result.get("source", "AI")
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
