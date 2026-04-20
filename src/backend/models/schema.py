from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

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
