#!/usr/bin/env fish
# Run tests for Z80 Binary Ninja plugin using uv

set -x FORCE_BINJA_MOCK 1

echo "🧪 Running Z80 plugin tests with uv..."

# Check if uv is installed
if not command -v uv > /dev/null
    echo "❌ uv is not installed. Please install it first:"
    echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
end

# Sync dependencies (uv handles venv automatically)
echo "📦 Syncing dependencies..."
uv sync --dev

# Run tests with coverage
echo "🧪 Running tests..."
uv run pytest -v --cov=. --cov-report=term-missing

# Run type checking if available
echo "🔍 Running type checking with pyright..."
uv run pyright; or begin
    echo "⚠️  pyright not available, trying mypy..."
    uv run mypy .
end

# Run linting
echo "🔍 Running linting with ruff..."
uv run ruff check .
uv run ruff format --check .

echo "✅ All tests completed!"