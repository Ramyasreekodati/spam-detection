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
        
        # Priority: Streamlit Secrets
        try:
            import streamlit as st
            if "GEMINI_API_KEY" in st.secrets:
                self.api_key = st.secrets["GEMINI_API_KEY"]
        except:
            pass
            
        if self.api_key:
            self.api_key = self.api_key.strip().replace('"', '').replace("'", "")
            
        self.model = None
        self.init_error = None
        self._initialize_model()

    def _initialize_model(self):
        try:
            if self.api_key and len(self.api_key) > 10:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-flash-latest')
                logger.info("✨ AI Engine Initialized Successfully")
            else:
                self.init_error = "GEMINI_API_KEY is missing or invalid."
                logger.warning(f"⚠️ {self.init_error}")
        except Exception as e:
            self.init_error = f"AI Initialization Error: {str(e)}"
            logger.error(f"💥 {self.init_error}")

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
            fallback = FallbackEngine.analyze(text)
            fallback["agentNotes"] = f"⚠️ {self.init_error or 'AI Service Busy'} | {fallback['agentNotes']}"
            return fallback

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

        # Final Fallback if all attempts fail
        fallback = FallbackEngine.analyze(text)
        error_msg = "AI Generation Failed (Rate Limit or Safety)"
        fallback["agentNotes"] = f"⚠️ {error_msg} | {fallback['agentNotes']}"
        return fallback
