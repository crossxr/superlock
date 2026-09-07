# ==============================================================================
# SuperLock Monorepo - Root Makefile
# ==============================================================================

.PHONY: help install setup dev dev-backend dev-frontend build build-backend build-frontend test test-backend lint clean cli-link

# Default target
help:
	@echo ""
	@echo "  ================================================================"
	@echo "    SuperLock Local Development Commands"
	@echo "  ================================================================"
	@echo ""
	@echo "  Setup & Dependencies:"
	@echo "    make install         Install all dependencies for backend, frontend, and CLI"
	@echo "    make setup           Init git submodules and prepare env files"
	@echo ""
	@echo "  Running Locally:"
	@echo "    make dev             Run both Backend (:8080) and Frontend (:3000) concurrently"
	@echo "    make dev-backend     Run Go API server locally on :8080"
	@echo "    make dev-frontend    Run Next.js frontend dashboard locally on :3000"
	@echo ""
	@echo "  Building:"
	@echo "    make build           Build both backend binary and frontend bundle"
	@echo "    make build-backend   Build Go server binary (superlock/backend/bin/server)"
	@echo "    make build-frontend  Build Next.js production bundle"
	@echo ""
	@echo "  Testing & Quality:"
	@echo "    make test            Run all backend and SDK tests"
	@echo "    make test-backend    Run Go backend unit and integration tests"
	@echo "    make lint            Run Go vet and frontend Next.js linter"
	@echo ""
	@echo "  CLI & Utilities:"
	@echo "    make cli-link        Link @superlock/cli globally for local terminal testing"
	@echo "    make clean           Clean build artifacts"
	@echo ""

# ------------------------------------------------------------------------------
# Setup & Installation
# ------------------------------------------------------------------------------

setup:
	@echo "==> Initializing git submodules..."
	git submodule update --init --recursive
	@if not exist "superlock\backend\.env" if exist "superlock\backend\.env.example" ( \
		echo "==> Creating superlock/backend/.env from .env.example..." && \
		copy superlock\backend\.env.example superlock\backend\.env \
	)

install: setup
	@echo "==> Installing Backend Go dependencies..."
	cd superlock/backend && go mod download
	@echo "==> Installing Frontend npm packages..."
	cd frontend && npm install
	@echo "==> Installing CLI npm packages..."
	cd superlock/cli && npm install
	@echo "==> All dependencies installed successfully!"

# ------------------------------------------------------------------------------
# Local Development
# ------------------------------------------------------------------------------

dev-backend:
	@echo "==> Starting SuperLock Backend on http://localhost:8080..."
	cd superlock/backend && go run ./cmd/server

dev-frontend:
	@echo "==> Starting SuperLock Dashboard on http://localhost:3000..."
	cd frontend && npm run dev

dev:
	@echo "==> Starting Backend and Frontend concurrently..."
	npx -y concurrently -k -n "backend,frontend" -c "cyan,yellow" \
		"cd superlock/backend && go run ./cmd/server" \
		"cd frontend && npm run dev"

# ------------------------------------------------------------------------------
# Building
# ------------------------------------------------------------------------------

build-backend:
	@echo "==> Building Backend Go binary..."
	cd superlock/backend && go build -o bin/server ./cmd/server

build-frontend:
	@echo "==> Building Frontend Next.js app..."
	cd frontend && npm run build

build: build-backend build-frontend
	@echo "==> Build completed successfully!"

# ------------------------------------------------------------------------------
# Testing & Code Quality
# ------------------------------------------------------------------------------

test-backend:
	@echo "==> Running Backend Go tests..."
	cd superlock/backend && go test -v ./...

test: test-backend
	@echo "==> All tests passed!"

lint-backend:
	@echo "==> Running Go vet..."
	cd superlock/backend && go vet ./...

lint-frontend:
	@echo "==> Running Frontend linter..."
	cd frontend && npm run lint

lint: lint-backend lint-frontend
	@echo "==> Lint checks completed!"

# ------------------------------------------------------------------------------
# CLI & Cleanup
# ------------------------------------------------------------------------------

cli-link:
	@echo "==> Linking @superlock/cli globally..."
	cd superlock/cli && npm link
	@echo "==> Linked! You can now run 'superlock --help' in your terminal."

clean:
	@echo "==> Cleaning build artifacts..."
	-rmdir /s /q superlock\backend\bin 2>nul
	-rmdir /s /q frontend\.next 2>nul
	@echo "==> Cleaned!"
