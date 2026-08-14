#!/bin/bash
# Run Chain-Trace API server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv backend/venv
fi

source backend/venv/bin/activate

if ! pip show uvicorn > /dev/null 2>&1; then
    echo "Installing dependencies..."
    pip install -r backend/requirements.txt
fi

echo "Starting Chain-Trace API server on http://localhost:8000"
uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000