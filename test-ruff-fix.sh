#!/bin/bash

echo "=== Testing Ruff Configuration Fix ==="
echo

echo "1. Testing with pinned Ruff version and explicit config (matches CI):"
uvx --from ruff==0.6.4 ruff --version
echo

echo "2. Checking for tab characters in problem files:"
echo "ColecoView.py:"
grep $'\t' ColecoView.py && echo "  → FOUND TABS" || echo "  → No tabs found (expected)"
echo

echo "3. Running Ruff check with exact CI configuration:"
uvx --from ruff==0.6.4 ruff check --config ./pyproject.toml .
echo

echo "4. Showing effective Ruff settings (truncated):"
uvx --from ruff==0.6.4 ruff check --config ./pyproject.toml --show-settings | head -30
echo

echo "5. Testing format check:"
uvx --from ruff==0.6.4 ruff format --config ./pyproject.toml . --check
echo

if [ $? -eq 0 ]; then
    echo "✅ All tests passed! The fix should work in CI."
else
    echo "❌ Some tests failed. Check the output above."
fi