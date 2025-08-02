#!/usr/bin/env fish
# Run tests for Z80 Binary Ninja plugin

set -x FORCE_BINJA_MOCK 1

# Check if we're in a virtual environment
if not set -q VIRTUAL_ENV
    echo "⚠️  No virtual environment active. Creating one..."
    python3 -m venv venv
    source venv/bin/activate.fish
    echo "📦 Installing dependencies..."
    pip install -e .
    pip install -e /Users/mblsha/Library/Application\ Support/Binary\ Ninja/plugins/binja-test-mocks
    pip install pytest pytest-cov
end

echo "🧪 Running Z80 plugin tests..."
pytest -v --cov=. --cov-report=term-missing

# Run type checking if available
if command -v pyright > /dev/null
    echo "🔍 Running type checking with pyright..."
    pyright
else if command -v mypy > /dev/null
    echo "🔍 Running type checking with mypy..."
    mypy .
end

# Run linting if available
if command -v ruff > /dev/null
    echo "🔍 Running linting with ruff..."
    ruff check .
end