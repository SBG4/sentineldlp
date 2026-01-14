# SentinelDLP Makefile
# Convenient commands for Docker operations
#
# Usage:
#   make help      - Show available commands
#   make build     - Build Docker images
#   make up        - Start all services
#   make down      - Stop all services
#   make logs      - View logs

.PHONY: help build up down restart logs ps clean prune shell-backend shell-frontend test health

# Default target
help:
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║           SentinelDLP Docker Management Commands              ║"
	@echo "╠═══════════════════════════════════════════════════════════════╣"
	@echo "║  make build          Build Docker images                      ║"
	@echo "║  make up             Start all services (detached)            ║"
	@echo "║  make down           Stop all services                        ║"
	@echo "║  make restart        Restart all services                     ║"
	@echo "║  make logs           View logs (follow mode)                  ║"
	@echo "║  make ps             Show running containers                  ║"
	@echo "║  make health         Check service health                     ║"
	@echo "║  make shell-backend  Open shell in backend container          ║"
	@echo "║  make shell-frontend Open shell in frontend container         ║"
	@echo "║  make clean          Stop services and remove containers      ║"
	@echo "║  make prune          Clean + remove volumes (DATA LOSS!)      ║"
	@echo "║  make dev            Start in development mode (with logs)    ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""

# Build Docker images
build:
	@echo "🔨 Building Docker images..."
	docker compose build

# Build without cache
build-fresh:
	@echo "🔨 Building Docker images (no cache)..."
	docker compose build --no-cache

# Start services
up:
	@echo "🚀 Starting SentinelDLP..."
	docker compose up -d
	@echo ""
	@echo "✅ SentinelDLP is starting up!"
	@echo "   Frontend: http://localhost:$${FRONTEND_PORT:-8080}"
	@echo ""
	@echo "   Run 'make logs' to view logs"
	@echo "   Run 'make health' to check service status"

# Stop services
down:
	@echo "🛑 Stopping SentinelDLP..."
	docker compose down

# Restart services
restart: down up

# View logs
logs:
	docker compose logs -f

# View logs for specific service
logs-backend:
	docker compose logs -f backend

logs-frontend:
	docker compose logs -f frontend

# Show container status
ps:
	docker compose ps

# Health check
health:
	@echo "🏥 Checking service health..."
	@echo ""
	@echo "Backend:"
	@curl -s http://localhost:$${FRONTEND_PORT:-8080}/api/stats | head -c 100 && echo "... ✅" || echo "❌ Backend unhealthy"
	@echo ""
	@echo "Frontend:"
	@curl -s http://localhost:$${FRONTEND_PORT:-8080}/health && echo " ✅" || echo "❌ Frontend unhealthy"
	@echo ""
	@echo "Container Status:"
	@docker compose ps

# Shell access
shell-backend:
	docker compose exec backend /bin/bash

shell-frontend:
	docker compose exec frontend /bin/sh

# Development mode (foreground with logs)
dev:
	@echo "🔧 Starting in development mode..."
	docker compose up

# Clean up containers
clean:
	@echo "🧹 Cleaning up containers..."
	docker compose down --remove-orphans

# Full cleanup including volumes (WARNING: Data loss!)
prune:
	@echo "⚠️  WARNING: This will delete all data!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "🗑️  Removing containers and volumes..."
	docker compose down -v --remove-orphans
	@echo "✅ Cleanup complete"

# Test API
test:
	@echo "🧪 Testing API endpoints..."
	@echo ""
	@echo "GET /api/stats:"
	@curl -s http://localhost:$${FRONTEND_PORT:-8080}/api/stats | python3 -m json.tool 2>/dev/null || echo "Failed"
	@echo ""
	@echo "GET /api/incidents:"
	@curl -s "http://localhost:$${FRONTEND_PORT:-8080}/api/incidents?limit=5" | python3 -m json.tool 2>/dev/null || echo "Failed"

# Setup environment file
setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env file from .env.example"; \
		echo "📝 Please edit .env and add your ANTHROPIC_API_KEY"; \
	else \
		echo "ℹ️  .env file already exists"; \
	fi

# Quick start (setup + build + up)
quickstart: setup build up
	@echo ""
	@echo "🎉 SentinelDLP is ready!"
	@echo "   Open http://localhost:$${FRONTEND_PORT:-8080} in your browser"
