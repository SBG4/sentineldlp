#!/bin/bash

# SentinelDLP - Sensitive Information Detection System
# Startup Script

echo "╔════════════════════════════════════════════════════════════╗"
echo "║            SentinelDLP - Starting Services                 ║"
echo "╚════════════════════════════════════════════════════════════╝"

cd "$(dirname "$0")"

# Check if Python dependencies are installed
if ! pip show fastapi > /dev/null 2>&1; then
    echo "[*] Installing Python dependencies..."
    pip install -r backend/requirements.txt --break-system-packages -q
fi

# Create data directory if not exists
mkdir -p data

# Start Backend API (background)
echo "[*] Starting Backend API on http://localhost:8000"
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 2

# Start Frontend (simple HTTP server)
echo "[*] Starting Frontend on http://localhost:3000"
cd frontend
python -m http.server 3000 &
FRONTEND_PID=$!
cd ..

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Services Started!                       ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Frontend:  http://localhost:3000                          ║"
echo "║  API:       http://localhost:8000                          ║"
echo "║  API Docs:  http://localhost:8000/docs                     ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Press Ctrl+C to stop all services                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Trap to cleanup on exit
cleanup() {
    echo ""
    echo "[*] Shutting down services..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup INT TERM

# Keep script running
wait
