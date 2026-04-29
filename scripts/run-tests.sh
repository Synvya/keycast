#!/bin/bash
set -e

# ABOUTME: Optimized test runner for Keycast local development.
# ABOUTME: Resets the test database and uses cargo-nextest for parallel execution.

# Ensure we are in the project root
cd "$(dirname "$0")/.."

echo "🧪 Starting Keycast Test Suite..."

# 1. Ensure master key exists
if [ ! -f "master.key" ]; then
    echo "🔑 Generating master key..."
    ./scripts/generate_key.sh
fi

# 2. Reset Database State
# We drop and recreate the test database to ensure absolute isolation between runs.
echo "📊 Resetting test database..."
# Use the default postgres DB to perform administrative tasks
PG_PASS=${POSTGRES_PASSWORD:-pass-apr-2026-local}
ADMIN_DB_URL="postgres://postgres:${PG_PASS}@localhost:5432/postgres"

docker exec keycast-postgres psql "$ADMIN_DB_URL" -c "DROP DATABASE IF EXISTS keycast_test WITH (FORCE);" > /dev/null
docker exec keycast-postgres createdb -U postgres keycast_test > /dev/null

# 3. Run Migrations
# Ensure the schema is up-to-date before running tests.
echo "🏗️  Running migrations..."
export DATABASE_URL="postgres://postgres:${PG_PASS}@localhost:5432/keycast_test"
cargo run --bin keycast -- --migrate

# 4. Set Test Environment
export REDIS_URL=${REDIS_URL:-redis://localhost:16379}
export TEST_REDIS_URL=${TEST_REDIS_URL:-redis://localhost:16379}

# 5. Run Tests
# Optimization: Parallelize unit tests, but serialize integration tests to prevent DB collisions.
echo "🚀 Running unit and core tests (parallel)..."
cargo nextest run --workspace --lib

echo "🚀 Running integration tests (serialized)..."
cargo nextest run --workspace --features integration-tests -j 1

echo "✅ All tests passed!"