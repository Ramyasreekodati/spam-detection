import streamlit as st
st.set_page_config(page_title="AI Agentic Security Dashboard", layout="wide", page_icon="🛡️")

import pandas as pd
import os
import time
from datetime import datetime
from dotenv import load_dotenv
from src.frontend.services.api_client import APIClient

# Load ENV & Configuration
load_dotenv()
API_KEY = os.getenv("API_KEY")
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

# Initialize API Client
if "api_client" not in st.session_state:
    st.session_state.api_client = APIClient(BACKEND_URL, API_KEY)

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
    
    # Auto-load API Key from ENV
    api_key = API_KEY
    if not api_key:
        st.error("🔑 API_KEY not found in .env")
    else:
        st.sidebar.success("📡 Internal AI Engine Active")
        st.sidebar.info("🔑 Cloud Auth Active")

    st.divider()
    st.markdown("### 💬 Quick Assistant")
    q_query = st.text_area("Is this safe?", placeholder="Paste snippet here...")
    if st.button("Ask Assistant"):
        if q_query:
            with st.spinner("Analyzing..."):
                data = st.session_state.api_client.analyze_message(q_query, session_id="quick-check")
                
                if "error" not in data:
                    lvl = data.get('threatLevel', 'UNKNOWN')
                    st.info(f"Team Verdict: {lvl}")
                    st.write(data.get('agentResponse'))
                else:
                    st.error(data["error"])
        else: st.warning("Please enter text.")

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
        st.markdown("""
            <div class='glass-card'>
                <h3 style='color:#3a7bd5;'>👋 Welcome to AI Security Dashboard</h3>
                <p>To start scanning your emails for threats, you need to connect your Gmail account securely. Follow these 3 quick steps:</p>
            </div>
        """, unsafe_allow_html=True)
        
        with st.expander("🛠️ STEP 1: Enable 2-Step Verification", expanded=True):
            st.write("Google requires 2-Step Verification to be active before you can create an App Password.")
            st.link_button("Go to Google Security Settings", "https://myaccount.google.com/security")
            st.caption("Ensure '2-Step Verification' is marked as ON.")

        with st.expander("🔑 STEP 2: Generate App Password"):
            st.write("Instead of your regular password, you must use a unique 16-digit 'App Password'.")
            st.markdown("""
            1. Search for **'App Passwords'** in your Google Account search bar.
            2. Select **'Mail'** and **'Other (Custom name)'**.
            3. Name it `AI Security Dashboard` and click **Generate**.
            4. Copy the **16-digit code** and paste it into the sidebar here.
            """)
            st.link_button("Generate App Password", "https://myaccount.google.com/apppasswords")

        with st.expander("📡 STEP 3: Enable IMAP Access"):
            st.write("This allows our AI Agent to read and audit your emails for security threats.")
            st.markdown("""
            1. Open **Gmail Settings** in your browser.
            2. Go to the **'Forwarding and POP/IMAP'** tab.
            3. Select **'Enable IMAP'** and click **Save Changes**.
            """)
            st.link_button("Open Gmail IMAP Settings", "https://mail.google.com/mail/u/0/#settings/fwdandimap")
            
        st.info("💡 Once you've completed these steps, enter your credentials in the sidebar to unlock the dashboard.")
        st.stop()
    
    if not api_key:
        st.error("❌ API Key is missing. Scanning disabled.")
        st.stop()

    try:
        if st.button("🚀 INITIALIZE GLOBAL SCAN", use_container_width=True):
            import imaplib
            import email
            from email.header import decode_header
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with st.spinner("Connecting to IMAP..."):
                import re
                user_clean = gmail_user.strip()
                pass_clean = re.sub(r'\s+', '', app_pass).strip()
                
                add_log(f"Initializing IMAP connection to {user_clean}...")
                try:
                    mail = imaplib.IMAP4_SSL("imap.gmail.com")
                    mail.login(user_clean, pass_clean)
                    mail.select("inbox")
                except Exception as e:
                    if "AUTHENTICATIONFAILED" in str(e):
                        st.error("❌ **Login Failed.** Please ensure your App Password and IMAP settings are correct.")
                    else:
                        st.error(f"❌ IMAP Error: {e}")
                    st.stop()
            
            _, messages = mail.search(None, 'ALL')
            ids = messages[0].split()[-50:] # Last 50 emails
            
            add_log(f"Found {len(ids)} emails. Fetching content...")
            
            # 1. Faster Fetching: Fetch all 50 emails in one go
            if ids:
                fetch_ids = b",".join(ids)
                _, msg_data = mail.fetch(fetch_ids, "(RFC822)")
                
                parsed_emails = []
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        # Extract Subject
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
                        
                        parsed_emails.append({
                            "subject": subject,
                            "from": sender,
                            "body": body,
                            "raw_id": "batch"
                        })

                # 2. Parallel AI Analysis
                add_log(f"Starting Multi-Agent Parallel Audit (5 workers)...")
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Pass api_client as a local variable to the task to avoid session_state thread issues
                client = st.session_state.api_client
                
                def analyze_task(email_item, client_obj):
                    return client_obj.scan_email(
                        email_id="batch",
                        sender=email_item["from"],
                        subject=email_item["subject"],
                        body=email_item["body"][:2000]
                    ), email_item

                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = {executor.submit(analyze_task, e, client): e for e in parsed_emails}
                    
                    for idx, future in enumerate(as_completed(futures)):
                        analysis, email_item = future.result()
                        
                        if "error" in analysis:
                            add_log(f"⚠️ Analysis Failed for {email_item['subject'][:20]}: {analysis['error']}")
                            analysis = {
                                "scamDetected": False, "threatLevel": "ERROR", "riskScore": 0, 
                                "confidence": 0, "agentNotes": analysis['error'], "agentReports": [],
                                "extractedIntelligence": {}, "source": "TIMEOUT"
                            }
                        
                        st.session_state.emails.append({
                            "id": len(st.session_state.emails),
                            "subject": email_item["subject"],
                            "from": email_item["from"],
                            "body": email_item["body"][:500],
                            "analysis": analysis
                        })
                        
                        # Update Progress
                        progress_val = (idx + 1) / len(parsed_emails)
                        progress_bar.progress(progress_val)
                        status_text.text(f"Processed {idx+1}/{len(parsed_emails)} emails...")

                # Clean up session state to keep only last 50
                if len(st.session_state.emails) > 50:
                    st.session_state.emails = st.session_state.emails[-50:]

            mail.logout()
            add_log("Scan Complete.")
            st.success("✅ Global Scan Completed!")
            st.rerun()
    except Exception as e:
        st.error(f"Scan Failed: {e}")

    # Display Feed with Filtering
    st.markdown("---")
    c1, c2 = st.columns([3, 1])
    with c1: st.markdown("### 🗂️ Analysis Feed")
    with c2: filter_lvl = st.selectbox("Filter By:", ["All", "High Risk", "Suspicious", "Safe"])
    
    for e in reversed(st.session_state.emails):
        analysis = e.get('analysis', {})
        lvl = analysis.get('threatLevel', 'UNKNOWN')
        
        # Apply Filter
        if filter_lvl == "High Risk" and lvl != "HIGH": continue
        if filter_lvl == "Suspicious" and lvl not in ["MEDIUM", "LOW"]: continue
        if filter_lvl == "Safe" and lvl != "SAFE": continue

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
                data = st.session_state.api_client.analyze_message(user_input, session_id="assistant-tab")
                
                if "error" not in data:
                    lvl = data.get('threatLevel', 'UNKNOWN')
                    score = data.get('riskScore', 0)
                    if lvl == "HIGH": st.error(f"🚨 HIGH RISK DETECTED ({score}%)")
                    elif lvl in ["MEDIUM", "LOW"]: st.warning(f"⚠️ SUSPICIOUS ({score}%)")
                    else: st.success(f"✅ SAFE ({score}%)")
                    
                    if data.get('source') == "FALLBACK": st.info("⚙️ AI system busy, running backup analysis...")
                    
                    st.markdown(f"**Reasoning:** {data.get('agentNotes', 'No additional notes.')}")
                    st.markdown("**Evidence Found:**")
                    st.json(data.get('extractedIntelligence', {}))

                    # Add to history for metrics and dashboard feed
                    st.session_state.emails.append({
                        "id": len(st.session_state.emails),
                        "subject": "Manual Analysis",
                        "from": "Direct Input",
                        "body": user_input[:500],
                        "analysis": data
                    })
                else:
                    st.error(data["error"])
        else: st.warning("Please enter some text.")

with tab_analytics:
    st.markdown("### 🧬 Multi-Agent Forensic Distribution")
    if st.session_state.emails:
        c1, c2 = st.columns(2)
        
        with c1:
            st.markdown("**🛡️ Risk Level Distribution**")
            df_risk = pd.DataFrame([{"Level": e['analysis']['threatLevel']} for e in st.session_state.emails])
            st.bar_chart(df_risk['Level'].value_counts())
            
        with c2:
            st.markdown("**🤖 Agent Participation**")
            all_reports = []
            for e in st.session_state.emails:
                for report in e['analysis'].get('agentReports', []):
                    all_reports.append(report)
            if all_reports:
                df_agents = pd.DataFrame(all_reports)
                st.bar_chart(df_agents['agent_name'].value_counts())
        
        st.markdown("---")
        st.markdown("**📋 Detailed Risk Analysis**")
        df_table = pd.DataFrame([{
            "Subject": e['subject'][:30] + "...",
            "Threat": e['analysis']['threatLevel'],
            "Score": f"{e['analysis']['riskScore']}%",
            "Agents": len(e['analysis'].get('agentReports', []))
        } for e in st.session_state.emails])
        st.dataframe(df_table, use_container_width=True)
    else:
        st.info("No scan data available. Run an audit to see forensics.")
