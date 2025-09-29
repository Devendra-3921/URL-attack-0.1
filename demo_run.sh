#!/bin/bash
# Demo runner for local testing (Linux / Termux)
set -e
echo "Starting Flask app..."
python3 -m venv venv || true
source venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.py
# run in background
python3 app.py &
sleep 2
echo "Sending example API request..."
curl -s -X POST http://127.0.0.1:8000/api/scan -H "Content-Type: application/json" -d '{"url":"http://example.com/?id=1 OR 1=1"}' | jq
echo "Open http://127.0.0.1:8000 in your browser to use the UI"
