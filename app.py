import streamlit as st
import pandas as pd
import requests
import time
import os
from datetime import datetime
from dotenv import load_dotenv

# Load ENV
load_dotenv()

# Page Config
st.set_page_config(page_title="AI Agentic Security Dashboard", layout="wide", page_icon="🛡️")

# Custom CSS for Premium Design
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@300;400;600&display=swap');
    
    .stApp { 
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
        color: #1a1a1a; 
        font-family: 'Inter', sans-serif; 
    }
    .main-title { 
        font-family: 'Orbitron', sans-serif; 
        background: linear-gradient(90deg, #00d2ff, #3a7bd5); 
        -webkit-background-clip: text; 
        -webkit-text-fill-color: transparent; 
        font-size: 3.5rem; 
        font-weight: 700; 
        margin-bottom: 2rem;
        text-shadow: 2px 2px 10px rgba(0, 0, 0, 0.1);
    }
    .glass-card { 
        background: rgba(255, 255, 255, 0.7); 
        border: 1px solid rgba(255, 255, 255, 0.3); 
        border-radius: 20px; 
        padding: 25px; 
        backdrop-filter: blur(15px); 
        margin-bottom: 25px;
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.1);
        color: #1a1a1a;
    }
    .stMetric { background: rgba(255, 255, 255, 0.5); padding: 15px; border-radius: 15px; border: 1px solid rgba(255, 255, 255, 0.2); }
    .status-badge { padding: 5px 15px; border-radius: 20px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
    .risk-high { background: rgba(255, 59, 48, 0.2); color: #ff3b30; border: 1px solid #ff3b30; }
    .risk-med { background: rgba(255, 159, 10, 0.2); color: #ff9f0a; border: 1px solid #ff9f0a; }
    .risk-low { background: rgba(52, 199, 89, 0.2); color: #34c759; border: 1px solid #34c759; }
    .system-log { font-family: 'Courier New', monospace; font-size: 0.85rem; color: #00ff41; background: #000; padding: 10px; border-radius: 5px; height: 300px; overflow-y: auto; }
    </style>
""", unsafe_allow_html=True)

# Session State Initialization
if "emails" not in st.session_state: st.session_state.emails = []
if "system_logs" not in st.session_state: st.session_state.system_logs = []
if "intelligence_repo" not in st.session_state: st.session_state.intelligence_repo = pd.DataFrame(columns=["upi", "banks", "links", "phones"])
if "automation_active" not in st.session_state: st.session_state.automation_active = False

def add_log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.system_logs.append(f"[{timestamp}] {msg}")
    # Memory management for logs
    if len(st.session_state.system_logs) > 100:
        st.session_state.system_logs.pop(0)

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
    st.markdown("### 🛠️ Agent Control")
    st.session_state.automation_active = st.toggle("Enable Autonomous Actions", value=st.session_state.automation_active)
    
    if st.button("🗑️ Clear Scan History", use_container_width=True):
        st.session_state.emails = []
        st.session_state.system_logs = []
        add_log("System state reset by user.")
        st.rerun()
    
    st.divider()
    st.markdown("### 🔐 Connection")
    gmail_user = st.text_input("Gmail Address", placeholder="example@gmail.com")
    app_pass = st.text_input("App Password", type="password", help="16-digit Google App Password")
    backend_url = st.text_input("API Backend", value="http://localhost:8000")
    api_backend_key = os.getenv("API_KEY")
    api_key = st.text_input("X-API-KEY", type="password", value=api_backend_key if api_backend_key else "", help="This should be loaded automatically from your .env file.")
    
    if not api_key:
        st.error("🔑 API Key Missing! Check your .env file.")
    else:
        # Masked debug log for verification
        masked_fe_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "****"
        st.sidebar.caption(f"Backend Auth Active: {masked_fe_key}")
    
    with st.expander("❓ How to get App Password"):
        st.markdown("""
        1. Enable 2FA on your Google Account.
        2. Go to [App Passwords](https://myaccount.google.com/apppasswords).
        3. Create a new app name (e.g. 'Spam Finder').
        4. Copy the 16-character code here.
        5. **Note:** Ensure IMAP is enabled in Gmail Settings > Forwarding and POP/IMAP.
        """)
    
    st.divider()
    st.markdown("### 💬 Quick Assistant")
    q_query = st.text_area("Is this safe?", placeholder="Paste snippet here...")
    if st.button("Ask Assistant"):
        if not api_key:
            st.warning("⚠️ Please provide an API Key in the sidebar.")
            st.stop()
        
        q_query = q_query.strip()
        if q_query:
            try:
                headers = {"x-api-key": api_key}
                res = requests.post(f"{backend_url}/webhook", json={"sessionId": "q", "message": {"sender": "user", "text": q_query, "timestamp": ""}}, headers=headers, timeout=5)
                if res.status_code == 401:
                    st.error("🔑 API Key Mismatch: Unauthorized Access.")
                    st.stop()
                res.raise_for_status()
                data = res.json()
                lvl = data.get('threatLevel', 'UNKNOWN')
                status = "🔴 HIGH RISK" if lvl == "HIGH" else ("🟡 SUSPICIOUS" if lvl in ["MEDIUM", "LOW"] else "🟢 SAFE")
                st.write(f"**Result:** {status}")
                if data.get('source') == "FALLBACK": st.info("Backup analysis active.")
            except Exception as e: 
                st.error(f"Offline or Error: {e}")
        else:
            st.warning("Please enter text.")

# Main Dashboard
st.markdown("<h1 class='main-title'>🛡️ AI Agentic Security Dashboard</h1>", unsafe_allow_html=True)

# Top Stats
c1, c2, c3, c4, c5 = st.columns(5)
total = len(st.session_state.emails)
spam = len([e for e in st.session_state.emails if e.get('analysis', {}).get('scamDetected', False)])
high = len([e for e in st.session_state.emails if e.get('analysis', {}).get('threatLevel') == "HIGH"])
safe = total - spam
avg_conf = sum([e.get('analysis', {}).get('confidence', 0) for e in st.session_state.emails]) / total if total > 0 else 0

c1.metric("Emails Scanned", total)
c2.metric("Spam Detected", spam, delta=f"+{spam}", delta_color="inverse")
c3.metric("High-Risk", high, delta=f"+{high}", delta_color="inverse")
c4.metric("Safe Emails", safe, delta=f"+{safe}")
c5.metric("Avg Confidence", f"{avg_conf*100:.1f}%")

tab_dashboard, tab_monitor, tab_assistant, tab_analytics = st.tabs(["📊 Dashboard", "📺 Live Monitor", "💬 AI Assistant", "📈 Analytics"])

with tab_dashboard:
    if not gmail_user or not app_pass:
        st.error("❌ Please enter your Gmail address and App Password in the sidebar.")
        st.stop()
    
    if not api_key:
        st.error("❌ API Key is missing. Scanning disabled.")
        st.stop()

    try:
        if st.button("🚀 INITIALIZE GLOBAL SCAN", use_container_width=True):
            import imaplib
            import email
            from email.header import decode_header
            
            with st.spinner("Connecting to IMAP..."):
                add_log(f"Initializing IMAP connection to {gmail_user}...")
                mail = imaplib.IMAP4_SSL("imap.gmail.com")
                mail.login(gmail_user, app_pass)
                mail.select("inbox")
            
            _, messages = mail.search(None, 'ALL')
            ids = messages[0].split()[-20:] # Reduced to 20 for faster scan
            
            add_log(f"Found {len(ids)} emails. Starting Multi-Agent Audit...")
            progress_bar = st.progress(0)
            
            for idx, e_id in enumerate(reversed(ids)):
                progress_val = (idx + 1) / len(ids)
                progress_bar.progress(progress_val)
                
                _, msg_data = mail.fetch(e_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        # Robust Subject Decoding
                        raw_subject = msg.get("Subject")
                        subject = ""
                        if raw_subject:
                            decoded_parts = decode_header(raw_subject)
                            for content, encoding in decoded_parts:
                                if isinstance(content, bytes):
                                    subject += content.decode(encoding or "utf-8", errors="ignore")
                                else:
                                    subject += str(content)
                        
                        sender = msg.get("From", "Unknown Sender")
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    payload = part.get_payload(decode=True)
                                    if payload: body = payload.decode(errors="ignore")
                        else:
                            payload = msg.get_payload(decode=True)
                            if payload: body = payload.decode(errors="ignore")
                        
                        add_log(f"Analyzing: {subject[:30]}...")
                        
                        # Call API
                        payload = {
                            "sessionId": f"scan-{e_id.decode()}",
                            "message": {"sender": sender, "text": body[:2000], "timestamp": datetime.now().isoformat()}
                        }
                        try:
                            headers = {"x-api-key": api_key}
                            res = requests.post(f"{backend_url}/webhook", json=payload, headers=headers, timeout=15)
                            if res.status_code == 401:
                                add_log("❌ Error: 401 Unauthorized - Check API Key.")
                                st.error("🔑 API Key Error: Dashboard Access Denied.")
                                st.stop()
                            res.raise_for_status()
                            analysis = res.json()
                        except Exception as api_err:
                            add_log(f"API Error: {api_err}")
                            analysis = {
                                "scamDetected": False, "threatLevel": "UNKNOWN", "riskScore": 0, 
                                "confidence": 0, "agentNotes": f"Connection Error: {api_err}", "agentReports": [],
                                "extractedIntelligence": {}, "source": "ERROR"
                            }
                        
                        email_data = {
                            "id": idx,
                            "subject": subject,
                            "from": sender,
                            "body": body[:500],
                            "analysis": analysis
                        }
                        
                        st.session_state.emails.append(email_data)
                        # Memory management for emails
                        if len(st.session_state.emails) > 50:
                            st.session_state.emails.pop(0)
                        
            mail.logout()
            add_log("Scan Complete.")
            st.success("✅ Global Scan Completed!")
            st.rerun()
    except Exception as e:
        st.error(f"Scan Failed: {e}")

    # Display Feed
    for e in reversed(st.session_state.emails):
        analysis = e.get('analysis', {})
        lvl = analysis.get('threatLevel', 'UNKNOWN')
        color = "#ff3b30" if lvl == "HIGH" else ("#ff9f0a" if lvl in ["MEDIUM", "LOW"] else "#34c759")
        icon = "🚨" if lvl == "HIGH" else ("⚠️" if lvl in ["MEDIUM", "LOW"] else "✅")
        status_label = "HIGH RISK" if lvl == "HIGH" else ("SUSPICIOUS" if lvl in ["MEDIUM", "LOW"] else ("SAFE" if lvl == "SAFE" else "UNKNOWN"))
        
        with st.container():
            st.markdown(f"""
                <div class='glass-card' style='border-left: 5px solid {color}'>
                    <div style='display:flex; justify-content:space-between;'>
                        <h4 style='margin:0;'>{e.get('subject', 'No Subject')}</h4>
                        <span style='color:{color}; font-weight:bold;'>{icon} {status_label} ({analysis.get('riskScore', 0)}%)</span>
                    </div>
                    <p style='font-size:0.8rem; color:#aaa;'>FROM: {e.get('from', 'Unknown')}</p>
                    {f"<p style='color:#ff9f0a; font-size:0.8rem;'>⚙️ AI Busy - Backup Scan Active</p>" if analysis.get('source') == 'FALLBACK' else ""}
                </div>
            """, unsafe_allow_html=True)
            
            with st.expander("🔍 Deep Forensic Report"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Agent Findings:**")
                    for report in analysis.get('agentReports', []):
                        st.caption(f"- {report.get('agent_name', 'Agent')}: {report.get('finding', 'No finding')}")
                with c2:
                    st.markdown("**Extracted Intel:**")
                    st.json(analysis.get('extractedIntelligence', {}))
                st.info(f"💡 AI Reasoning: {analysis.get('agentNotes', 'No reasoning provided.')}")

with tab_monitor:
    st.markdown("### 🖥️ Real-time Activity")
    log_content = "\n".join(st.session_state.system_logs)
    st.markdown(f"<div class='system-log'>{log_content}</div>", unsafe_allow_html=True)

with tab_assistant:
    st.markdown("### 💬 AI Scam Analysis Assistant")
    user_input = st.text_area("Paste email content:", height=150)
    if st.button("Analyze Now"):
        if not api_key:
            st.error("🔑 API Key is missing. Analysis disabled.")
            st.stop()
        user_input = user_input.strip()
        if user_input:
            with st.spinner("🕵️‍♂️ Investigating..."):
                try:
                    headers = {"x-api-key": api_key}
                    res = requests.post(f"{backend_url}/webhook", json={"sessionId": "assistant", "message": {"sender": "user", "text": user_input, "timestamp": ""}}, headers=headers, timeout=20)
                    if res.status_code == 401:
                        st.error("🔑 401 Unauthorized: The API Key provided in the sidebar is incorrect.")
                        st.stop()
                    res.raise_for_status()
                    data = res.json()
                    
                    lvl = data.get('threatLevel', 'UNKNOWN')
                    score = data.get('riskScore', 0)
                    if lvl == "HIGH": st.error(f"🚨 HIGH RISK DETECTED ({score}%)")
                    elif lvl in ["MEDIUM", "LOW"]: st.warning(f"⚠️ SUSPICIOUS ({score}%)")
                    else: st.success(f"✅ SAFE ({score}%)")
                    
                    if data.get('source') == "FALLBACK": st.info("⚙️ AI system busy, running backup analysis...")
                    
                    st.markdown(f"**Reasoning:** {data.get('agentNotes', 'No additional notes.')}")
                    st.markdown("**Evidence Found:**")
                    st.json(data.get('extractedIntelligence', {}))
                except Exception as e:
                    st.error(f"Failed to reach AI Backend: {e}")
        else: st.warning("Please enter some text.")

with tab_analytics:
    st.markdown("### 📈 Risk Distribution Analysis")
    if st.session_state.emails:
        # Create a list of dicts with subject and risk score
        chart_data = []
        for e in st.session_state.emails:
            subj = e.get('subject', 'No Subject')
            # Truncate for display
            display_name = (subj[:25] + '...') if len(subj) > 25 else subj
            chart_data.append({
                "Email": display_name,
                "Risk Score (%)": e.get('analysis', {}).get('riskScore', 0)
            })
            
        df = pd.DataFrame(chart_data)
        st.bar_chart(df, x="Email", y="Risk Score (%)", use_container_width=True)
        
        st.markdown("---")
        st.markdown("**Detailed Risk Table**")
        st.table(df)
    else:
        st.info("No scan data available yet. Run a scan from the Dashboard tab.")
