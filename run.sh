#!/bin/bash
# SafetyMonitor v11 — Secure launcher
echo "🏗️  SafetyMonitor v11 — Starting..."

# Install dependencies
pip install -r requirements.txt

# Run (dev mode — HTTP)
# For production with HTTPS: FORCE_HTTPS=1 SECRET_KEY=your_secret python app.py
python app.py
