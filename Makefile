.PHONY: help dev test lint type-check security migrate seed build clean ci

PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest

help:
	@echo "PySOAR Development Commands"
	@echo ""
	@echo "make dev          - Start local development environment"
	@echo "make test         - Run pytest with coverage"
	@echo "make lint         - Run ruff + black + isort"
	@echo "make type-check   - Run mypy type checking"
	@echo "make security     - Run bandit + safety checks"
	@echo "make migrate      - Run database migrations"
	@echo "make seed         - Seed database with initial data"
	@echo "make build        - Build Docker image"
	@echo "make clean        - Remove build artifacts and cache files"
	@echo "make ci           - Run all checks (lint + type-check + security + test)"
	@echo ""

dev:
	docker-compose -f docker-compose.dev.yml up -d
	@echo "Development environment started"
	@echo "API: http://localhost:8000"
	@echo "Docs: http://localhost:8000/docs"

dev-down:
	docker-compose -f docker-compose.dev.yml down

test:
	$(PYTEST) tests/ -v --cov=src --cov-report=html --cov-report=term-missing --cov-fail-under=50

test-fast:
	$(PYTEST) tests/ -v --cov=src -k "not slow"

test-integration:
	$(PYTEST) tests/integration -v --cov=src

lint:
	ruff check src/ tests/ --fix
	black src/ tests/
	isort src/ tests/

lint-check:
	ruff check src/ tests/
	black --check src/ tests/
	isort --check-only src/ tests/

type-check:
	mypy --ignore-missing-imports src/

security:
	bandit -r src/ -f csv -o bandit-report.csv
	safety check -r requirements.txt --json -o safety-report.json

security-full:
	@echo "Running Bandit..."
	bandit -r src/ -ll -ii
	@echo "Running Safety..."
	safety check -r requirements.txt
	@echo "Running pip-audit..."
	pip-audit -r requirements.txt

migrate:
	alembic upgrade head

migrate-down:
	alembic downgrade -1

migrate-new:
	@read -p "Enter migration name: " name; \
	alembic revision --autogenerate -m "$$name"

seed:
	$(PYTHON) -c "from src.services.seed import seed_database; import asyncio; asyncio.run(seed_database())"

build:
	docker build -t pysoar-backend:latest .

build-prod:
	docker build -t pysoar-backend:$(shell git describe --tags --always) .

run-docker:
	docker run -it --rm \
		-p 8000:8000 \
		-e DATABASE_URL="sqlite+aiosqlite:///./pysoar.db" \
		pysoar-backend:latest

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".coverage" -delete
	find . -name "coverage.xml" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name dist -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name build -exec rm -rf {} + 2>/dev/null || true

ci: lint type-check security test
	@echo "All CI checks passed!"

pre-commit-install:
	pre-commit install

pre-commit-run:
	pre-commit run --all-files

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"

format:
	black src/ tests/
	isort src/ tests/

docs:
	@echo "Building documentation..."
	@echo "API docs available at http://localhost:8000/docs"

version:
	@grep "version" pyproject.toml | head -1

.PHONY: help dev dev-down test test-fast test-integration lint lint-check type-check security security-full migrate migrate-down migrate-new seed build build-prod run-docker clean ci pre-commit-install pre-commit-run install install-dev format docs version
