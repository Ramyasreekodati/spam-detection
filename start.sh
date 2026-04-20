#!/bin/bash

# 1. Start the FastAPI backend in the background
# We bind to 0.0.0.0:8000 so the frontend can reach it
python backend.py &

# 2. Wait a few seconds for the backend to initialize
sleep 5

# 3. Start the Streamlit frontend
# Hugging Face REQUIRES the app to run on port 7860
streamlit run app.py --server.port 7860 --server.address 0.0.0.0
