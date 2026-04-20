import os
import json
import re
import asyncio
import logging
import google.generativeai as genai
from typing import Dict, Any, Optional
from .fallback_service import FallbackEngine

logger = logging.getLogger("AIService")

class AIService:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model = None
        self._initialize_model()

    def _initialize_model(self):
        try:
            if self.api_key:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-flash-latest')
                logger.info("✨ AI Engine Initialized Successfully")
            else:
                logger.warning("⚠️ GEMINI_API_KEY missing. AI features will be disabled.")
        except Exception as e:
            logger.error(f"💥 AI Initialization Error: {e}")

    def _clean_json_response(self, raw_text: str) -> Optional[Dict[str, Any]]:
        try:
            start = raw_text.find('{')
            end = raw_text.rfind('}')
            if start != -1 and end != -1:
                json_str = raw_text[start:end+1]
                json_str = re.sub(r'//.*', '', json_str) # Remove comments
                return json.loads(json_str)
            return None
        except Exception as e:
            logger.error(f"JSON Parse Error: {e}")
            return None

    def _validate_response(self, data: Any) -> bool:
        if not isinstance(data, dict): return False
        required = ["scamDetected", "threatLevel", "riskScore", "confidence", "agentNotes"]
        return all(k in data for k in required)

    async def analyze(self, text: str, history: str = "", retries: int = 2) -> Dict[str, Any]:
        if not self.model:
            return FallbackEngine.analyze(text)

        prompt = f"""
        ROLE: Lead Coordinator for a Multi-Agent Security Audit Team.
        
        AGENTS:
        1. PhishHunter (URL Specialist)
        2. MoneyGuard (Financial Specialist)
        3. NeuroSpy (Linguistic Specialist)
        
        TASK: Audit the email for malicious intent, phishing, or fraud.
        
        PROTOCOL:
        - Accuracy is priority. 
        - Newsletters are SAFE unless they request credentials.
        - High Risk (>85) requires explicit malicious triggers.
        
        OUTPUT SCHEMA (Strict JSON):
        {{
            "scamDetected": bool,
            "threatLevel": "HIGH" | "MEDIUM" | "LOW" | "SAFE",
            "riskScore": int(0-100),
            "confidence": float(0.0-1.0),
            "agentResponse": "Summary of findings",
            "agentNotes": "Technical forensic details",
            "xaiExplanations": ["Reason 1", "Reason 2"],
            "agentReports": [
                {{"agent_name": "PhishHunter", "finding": "...", "risk_contribution": int}},
                {{"agent_name": "MoneyGuard", "finding": "...", "risk_contribution": int}},
                {{"agent_name": "NeuroSpy", "finding": "...", "risk_contribution": int}}
            ],
            "bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []
        }}
        
        CONTEXT: {history}
        EMAIL CONTENT: {text[:3000]}
        """

        for attempt in range(retries + 1):
            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(self.model.generate_content, prompt),
                    timeout=25.0
                )
                data = self._clean_json_response(response.text)
                if data and self._validate_response(data):
                    data["source"] = "AI"
                    return data
            except Exception as e:
                logger.warning(f"AI Attempt {attempt+1} failed: {e}")
                if attempt < retries: await asyncio.sleep(1)

        return FallbackEngine.analyze(text)
