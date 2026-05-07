import re
from typing import Dict, Any

class FallbackEngine:
    SUSPICIOUS_KEYWORDS = [
        r"lottery", r"won", r"million", r"dollars", r"claim", r"prize", r"winner", 
        r"bank details", r"account number", r"password", r"otp", r"verify", r"urgent",
        r"blocked", r"suspended", r"login", r"click here", r"gift card", r"btc", r"crypto"
    ]
    SAFE_KEYWORDS = [
        r"unsubscribe", r"view in browser", r"newsletter", r"privacy policy", r"copyright", 
        r"sent by", r"preferences", r"no longer want to receive", r"digest"
    ]
    TRUSTED_DOMAINS = [
        "quora.com", "medium.com", "google.com", "substack.com", "nvidia.com", 
        "github.com", "microsoft.com", "linkedin.com", "apple.com"
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
        raw_links = re.findall(r'https?://\S+', text)
        findings["phishingLinks"] = raw_links
        
        # 3. Phone Numbers
        findings["phoneNumbers"] = re.findall(r'\+?\d{10,12}', text)
        
        # 4. Bank/UPI (with Context Logic)
        # Improved UPI regex: Excludes common email domains to prevent false financial flags
        all_handles = re.findall(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', text)
        common_email_domains = ['gmail', 'yahoo', 'outlook', 'hotmail', 'icloud', 'protonmail']
        findings["upiIds"] = [h for h in all_handles if not any(dom in h.lower() for dom in common_email_domains)]
        
        # Stricter Bank Detection: Only if context words exist
        potential_accounts = re.findall(r'\b\d{11,16}\b', text)
        context_words = ["account", "bank", "ifsc", "transfer", "deposit", "beneficiary"]
        if any(word in text_lower for word in context_words):
            findings["bankAccounts"] = potential_accounts
        else:
            findings["bankAccounts"] = [] # Treat as tracking IDs if no context
        
        # --- Risk Scoring Calculation ---
        # 1. Critical Scams (High Weight)
        bank_scams = re.findall(r'(bank|account|locked|suspended|verify|security|update|login|kyc|card)', text, re.I)
        urgency_patterns = re.findall(r'(immediately|asap|urgent|action required|within 24 hours|limited time)', text, re.I)
        shortened_links = re.findall(r'(bit\.ly|t\.co|tinyurl|goo\.gl|shorturl|is\.gd|buff\.ly)', text, re.I)

        # 2. Heuristic Scoring Logic
        score = 0
        if bank_scams and (urgency_patterns or shortened_links):
            score += 70 # Very high risk for bank + urgency/shortlink
        
        score += len(bank_scams) * 5
        score += len(urgency_patterns) * 10
        score += len(shortened_links) * 20
        score += len(findings["suspiciousKeywords"]) * 8
        
        # Capped Link Penalty (Fix 1)
        # We only penalize the first 3 unique links to avoid newsletter explosion
        unique_links = list(set(findings["phishingLinks"]))
        score += min(len(unique_links), 3) * 10
        
        # Trust Bonus (Fix 4)
        for link in unique_links:
            if any(domain in link.lower() for domain in FallbackEngine.TRUSTED_DOMAINS):
                score -= 15 # Deduct risk for trusted domains
        
        score += len(findings["phoneNumbers"]) * 10
        score += len(findings["upiIds"]) * 40
        score += len(findings["bankAccounts"]) * 25
        
        # Strong Newsletter Detection (Fix 3)
        is_newsletter = False
        for skw in FallbackEngine.SAFE_KEYWORDS:
            if re.search(skw, text_lower):
                score -= 50
                is_newsletter = True
                break
        
        # Normalize Score
        risk_score = max(0, min(score, 100))
        
        # Re-balanced Thresholds (Fix 5)
        if risk_score > 90: level = "HIGH"
        elif risk_score > 60: level = "MEDIUM"
        elif risk_score > 30: level = "LOW"
        else: level = "SAFE"
        
        # Detailed Reasoning for Transparency
        triggers = []
        if bank_scams: triggers.append(f"Banking Keywords: {len(bank_scams)}")
        if urgency_patterns: triggers.append(f"Urgency Patterns: {len(urgency_patterns)}")
        if shortened_links: triggers.append(f"Shortened/Obfuscated Links: {len(shortened_links)}")
        if findings["suspiciousKeywords"]: triggers.append(f"Keywords: {len(findings['suspiciousKeywords'])}")
        if findings["phoneNumbers"]: triggers.append(f"Phones: {len(findings['phoneNumbers'])}")
        if findings["upiIds"]: triggers.append(f"UPI IDs: {len(findings['upiIds'])}")
        if findings["bankAccounts"]: triggers.append(f"Bank Accounts: {len(findings['bankAccounts'])}")
        
        reasoning = "Rule-based scan complete. "
        if triggers:
            reasoning += "Detected: " + " | ".join(triggers)
        else:
            reasoning += "No specific malicious patterns detected."
        
        if is_newsletter: reasoning += " (Identified as safe newsletter/automated mail)"

        return {
            "scamDetected": risk_score > 30,
            "threatLevel": level,
            "riskScore": risk_score,
            "confidence": 0.7,
            "agentNotes": reasoning,
            "agentResponse": "I've analyzed this using my updated security heuristics.",
            "xaiExplanations": [f"Risk calibrated based on {len(unique_links)} links and domain trust."],
            "agentReports": [{"agent_name": "FallbackV2", "finding": "Heuristic calibration applied", "risk_contribution": risk_score}],
            "source": "FALLBACK",
            **findings
        }
