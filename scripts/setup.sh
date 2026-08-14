#!/bin/bash
# Setup and run Chain-Trace locally
# This script sets up both backend and frontend from a single command

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Chain-Trace Setup ==="
echo ""

# Install backend dependencies
echo "Setting up backend..."
cd "$PROJECT_ROOT/backend"

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "Installing Python dependencies..."
pip install --quiet -r requirements.txt

echo ""
echo "Backend setup complete!"
echo ""

# Install frontend dependencies
echo "Setting up frontend..."
cd "$PROJECT_ROOT/frontend"

if [ ! -d "node_modules" ]; then
    echo "Installing Node.js dependencies..."
    npm install --quiet
fi

echo ""
echo "Frontend setup complete!"
echo ""

echo "=== How to Run ==="
echo ""
echo "Run backend only:"
echo "  source backend/venv/bin/activate && cd backend && uvicorn api.main:app --port 8000"
echo ""
echo "Run frontend only:"
echo "  cd frontend && npm run dev"
echo ""
echo "Or run both (in separate terminals):"
echo "  Terminal 1: ./scripts/run_backend.sh"
echo "  Terminal 2: ./scripts/run_frontend.sh"
echo ""
echo "Open http://localhost:3000 to access the dashboard"
echo "Open http://localhost:8000/docs for API documentation"
echo ""