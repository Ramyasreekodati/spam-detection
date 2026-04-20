---
title: AI Agentic Security Dashboard
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# Agentic Honey-Pot for Scam Detection & Intelligence Extraction

This project is an AI-powered honeypot system designed to detect scam intent in emails and autonomously extract intelligence. It consists of a FastAPI backend and a Streamlit dashboard.

## 🚀 Features
- **Live Email Integration**: Connects to Gmail via IMAP (using 16-digit App Password).
- **AI-Powered Detection**: Uses Google Gemini to analyze email content for scam intent.
- **Intelligence Extraction**: Automatically extracts UPI IDs, Bank Accounts, Phishing Links, and Phone Numbers.
- **Hackathon Ready**: Implements the required REST API webhook and final callback to the GUVI evaluation endpoint.
- **Premium UI**: Sleek dark-themed Streamlit dashboard with real-time metrics.

## 🛠️ Setup Instructions

### 1. Prerequisites
- Python 3.9+
- A Google Account with 2FA enabled.
- A [Google App Password](https://myaccount.google.com/apppasswords) (16-digit).
- A [Gemini API Key](https://aistudio.google.com/app/apikey).

### 2. Installation
```bash
pip install -r requirements.txt
```

### 3. Running the System

You need to run both the backend and the app.

#### Step A: Start the Backend (API)
```bash
python backend.py
```
The backend will run on `http://localhost:8000`. It provides the `/webhook` endpoint required for the hackathon.

#### Step B: Start the Dashboard (App)
```bash
streamlit run app.py
```
The dashboard will open in your browser.

## 🔧 Configuration
- Enter your **Gmail address** and **16-digit App Password** in the sidebar.
- Enter your **Gemini API Key** to enable AI analysis.
- Click **"Fetch & Analyze 50 Emails"** to begin the process.

## 📝 API Endpoints
- `POST /webhook`: Accepts message events for scam analysis.
- **Callback**: Automatically sends final intelligence to `https://hackathon.guvi.in/api/updateHoneyPotFinalResult` when a scam is confirmed.
