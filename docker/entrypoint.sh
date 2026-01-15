#!/bin/bash
# SentinelDLP Backend Entrypoint
# Ensures data directories exist with correct permissions before starting the app

set -e

# Create data directories if they don't exist (handles Docker volume mounts)
mkdir -p /app/data/uploads /app/data/config

# Fix ownership for mounted volumes (run as root, then drop privileges)
chown -R sentineldlp:sentineldlp /app/data

# Check if a command was passed (e.g., for celery worker)
if [ $# -gt 0 ]; then
    # Run the passed command as sentineldlp user
    exec gosu sentineldlp "$@"
else
    # Default: start the FastAPI application
    exec gosu sentineldlp uvicorn main:app --host 0.0.0.0 --port 8000
fi
