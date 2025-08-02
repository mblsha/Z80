.PHONY: help install install-dev test test-verbose test-coverage lint format type-check clean build bn-install bn-uninstall

# Default target
help:
	@echo "Available targets:"
	@echo "  install       - Install package in production mode"
	@echo "  install-dev   - Install package with development dependencies"
	@echo "  test          - Run tests with pytest"
	@echo "  test-verbose  - Run tests with verbose output"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run linting with ruff"
	@echo "  format        - Format code with black and isort"
	@echo "  type-check    - Run type checking with mypy"
	@echo "  clean         - Remove build artifacts and cache files"
	@echo "  build         - Build distribution packages"
	@echo "  bn-install    - Install plugin to Binary Ninja (requires BN_PLUGINS env var)"
	@echo "  bn-uninstall  - Uninstall plugin from Binary Ninja"

# Installation targets
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pip install binja-test-mocks

# Testing targets
test:
	FORCE_BINJA_MOCK=1 pytest

test-verbose:
	FORCE_BINJA_MOCK=1 pytest -v

test-coverage:
	FORCE_BINJA_MOCK=1 pytest --cov --cov-report=html --cov-report=term

# Code quality targets
lint:
	ruff check .
	ruff format . --check

format:
	black .
	isort .
	ruff format .

type-check:
	mypy .

# Cleanup targets
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "*.egg" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +
	find . -type d -name "build" -exec rm -rf {} +

# Build targets
build: clean
	python -m build

# Development workflow
dev: install-dev
	@echo "Development environment ready!"

# Run all checks
check: lint type-check test
	@echo "All checks passed!"

# Binary Ninja specific targets
bn-install:
ifndef BN_PLUGINS
	$(error BN_PLUGINS is undefined)
endif
	@if [ -L "$(BN_PLUGINS)/Z80" ]; then \
		echo "already installed"; \
	else \
		echo "installing"; \
		ln -s "$(PWD)" "$(BN_PLUGINS)/Z80"; \
	fi

bn-uninstall:
ifndef BN_PLUGINS
	$(error BN_PLUGINS is undefined)
endif
	@if [ -L "$(BN_PLUGINS)/Z80" ]; then \
		echo "uninstalling"; \
		rm "$(BN_PLUGINS)/Z80"; \
	else \
		echo "not installed"; \
	fi

