import os
import time
import asyncio
from datetime import datetime
from src.backend.services.ai_service import AIService

class APIClient:
    def __init__(self, backend_url=None, api_key=None):
        self.api_key = api_key or os.getenv("API_KEY")
        # Initialize the AI Service directly inside the client for Streamlit Cloud
        self.ai_service = AIService()

    def analyze_message(self, message_text, sender="user", session_id="assistant", retries=3):
        try:
            # Handle asyncio event loop for Streamlit integration
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Call AI service directly
            if loop.is_running():
                # If loop is already running (unlikely for sync calls in Streamlit but possible)
                import nest_asyncio
                nest_asyncio.apply()
            
            result = loop.run_until_complete(self.ai_service.analyze(message_text))
            return result
        except Exception as e:
            return {"error": f"Internal AI Analysis failed: {str(e)}"}

    def scan_email(self, email_id, sender, subject, body):
        return self.analyze_message(
            message_text=body,
            sender=sender,
            session_id=f"scan-{email_id}"
        )
