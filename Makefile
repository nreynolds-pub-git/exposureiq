.DEFAULT_GOAL := help
.PHONY: help install install-backend install-frontend run run-backend run-frontend \
        pull test test-backend test-frontend lint lint-backend lint-frontend \
        format format-backend format-frontend clean docker-up docker-down

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
NPM ?= npm

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- Install ---

install: install-backend install-frontend  ## Install all dependencies

install-backend:  ## Install Python backend dependencies
	$(PIP) install -e ".[dev]"

install-frontend:  ## Install frontend dependencies
	cd frontend && $(NPM) install

# --- Run ---

run: docker-up  ## Run the full stack (Docker)

run-backend:  ## Run FastAPI dev server with auto-reload
	cd backend && $(PYTHON) -m uvicorn t1_cve_enricher.main:app --reload --host 0.0.0.0 --port 8000

run-frontend:  ## Run Vite frontend dev server
	cd frontend && $(NPM) run dev

pull:  ## Trigger an on-demand pipeline run
	$(PYTHON) -m t1_cve_enricher.workers.scheduler --run-now

# --- Test / lint / format ---

test: test-backend test-frontend  ## Run all tests

test-backend:  ## Run Python tests
	$(PYTHON) -m pytest --cov=t1_cve_enricher --cov-report=term-missing

test-frontend:  ## Run frontend tests
	cd frontend && $(NPM) test

lint: lint-backend lint-frontend  ## Lint everything

lint-backend:  ## Ruff + mypy
	$(PYTHON) -m ruff check backend/src backend/tests
	$(PYTHON) -m mypy backend/src

lint-frontend:  ## ESLint + tsc
	cd frontend && $(NPM) run lint
	cd frontend && $(NPM) run typecheck

format: format-backend format-frontend  ## Auto-format everything

format-backend:  ## Ruff format
	$(PYTHON) -m ruff format backend/src backend/tests
	$(PYTHON) -m ruff check --fix backend/src backend/tests

format-frontend:  ## Prettier
	cd frontend && $(NPM) run format

# --- Docker ---

docker-up:  ## Start the full stack with docker-compose
	docker-compose up --build

docker-down:  ## Stop and remove containers
	docker-compose down

# --- Misc ---

clean:  ## Remove build artifacts and caches
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	rm -rf frontend/dist frontend/node_modules/.cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
