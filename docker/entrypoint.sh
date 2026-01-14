#!/bin/bash
# SentinelDLP Backend Entrypoint
# Ensures data directories exist with correct permissions before starting the app

set -e

# Create data directories if they don't exist (handles Docker volume mounts)
mkdir -p /app/data/uploads /app/data/config

# Fix ownership for mounted volumes (run as root, then drop privileges)
chown -R sentineldlp:sentineldlp /app/data

# Drop privileges and start the application as sentineldlp user
exec gosu sentineldlp uvicorn main:app --host 0.0.0.0 --port 8000
