import requests
import os
import time
from datetime import datetime

class APIClient:
    def __init__(self, backend_url="http://127.0.0.1:8000", api_key=None):
        self.backend_url = backend_url
        self.api_key = api_key or os.getenv("API_KEY")

    def analyze_message(self, message_text, sender="user", session_id="assistant", retries=3):
        url = f"{self.backend_url}/webhook"
        headers = {"x-api-key": self.api_key}
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": sender,
                "text": message_text,
                "timestamp": datetime.now().isoformat()
            }
        }

        for attempt in range(retries):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=15)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 401:
                    return {"error": "Authentication failed. Check your API key."}
            except Exception as e:
                if attempt == retries - 1:
                    return {"error": f"Connection failed after {retries} attempts: {str(e)}"}
                time.sleep(1)
        return {"error": "Unknown error occurred during analysis."}

    def scan_email(self, email_id, sender, subject, body):
        return self.analyze_message(
            message_text=body,
            sender=sender,
            session_id=f"scan-{email_id}"
        )
