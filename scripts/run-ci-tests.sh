#!/bin/bash
set -e

# ABOUTME: CI/CD test runner for Keycast.
# Optimized for non-interactive environments and automated pipelines.

cd "$(dirname "$0")/.."

echo "🏗️  Starting CI Test Pass..."

# Standard CI environment variables (defaults to local docker-mode values if not set)
export DATABASE_URL=${DATABASE_URL:-postgres://postgres:password@localhost:5432/keycast_test}
export REDIS_URL=${REDIS_URL:-redis://localhost:16379}
export TEST_REDIS_URL=${TEST_REDIS_URL:-redis://localhost:16379}

# 1. Workspace-wide test run
echo "🧪 Running workspace tests..."
cargo nextest run --workspace

# 2. Specific feature/package integration tests
# (Matches existing CI requirements in package.json)
echo "🧪 Running integration-feature tests..."
cargo test -p keycast_core --features integration-tests --lib
cargo test -p keycast_api --features integration-tests --lib --tests
cargo test -p keycast_signer --features integration-tests --lib --tests

# 3. Ignored tests (Relays, etc)
echo "🧪 Running ignored cluster tests..."
cargo test -p cluster-hashring --lib -- --ignored

echo "🚀 CI Pass Complete!"
