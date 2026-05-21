# ─────────────────────────────────────────────────────────────────────────────
# Keycast Development Helper
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: check-prereq install-prereq setup migrate help dev test fmt fmt-check clippy ci ci-fast install-hooks env-local env-staging docker-build docker-up docker-down docker-logs support-admin-grant support-admin-revoke support-admin-list

# Default target: show help
all: help

help: ## Show this help message
	@echo "🔑 \033[1;32mSynvya Keycast\033[0m"
	@echo "Unified Nostr key management and event signing service."
	@echo ""
	@echo "\033[1;34mUsage:\033[0m"
	@echo "  make <target>"
	@echo ""
	@echo "\033[1;34mSetup & Environment:\033[0m"
	@grep -E '^[-a-zA-Z0-9_]+:.*?## (Setup|Environment).*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "\033[1;34mDevelopment & Testing:\033[0m"
	@grep -E '^[-a-zA-Z0-9_]+:.*?## (Development|Quality).*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "\033[1;34mDocker & Deployment:\033[0m"
	@grep -E '^[-a-zA-Z0-9_]+:.*?## Docker.*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# --- Setup & Environment ---

check-prereq: ## Setup: Verify Rust, Bun, and SQLX are installed
	@echo "==> Checking Keycast prerequisites..."
	@command -v cargo >/dev/null 2>&1 || (echo "  ✗ cargo (Rust) not found"; exit 1)
	@command -v bun >/dev/null 2>&1 || (echo "  ✗ bun not found"; exit 1)
	@command -v sqlx >/dev/null 2>&1 || (echo "  ✗ sqlx-cli not found. Run 'make install-prereq'"; exit 1)
	@echo "  ✓ All Keycast prerequisites met!"

install-prereq: ## Setup: Install sqlx-cli tool (required for migrations)
	@echo "==> Installing prerequisites..."
	cargo install sqlx-cli --no-default-features --features postgres
	cargo install cargo-nextest --locked

setup: ## Setup: Initialize .env and generate master key
	@echo "==> Initializing environment configuration (.env.local)..."
	@if [ ! -f ".env.local" ]; then bash scripts/init.sh --domain localhost --file .env.local; fi
	@if grep -q "SERVER_NSEC=$$" .env.local; then \
		echo "==> Generating SERVER_NSEC for .env.local..."; \
		RAND_SEC=$$(openssl rand -hex 32); \
		sed -i '' "s/SERVER_NSEC=.*/SERVER_NSEC=$$RAND_SEC/" .env.local || sed -i "s/SERVER_NSEC=.*/SERVER_NSEC=$$RAND_SEC/" .env.local; \
	fi
	@if [ ! -f "master.key" ]; then bun run key:generate; fi
	@$(MAKE) env-local
	@$(MAKE) install-hooks
	@echo "  ✓ Setup complete."

env-local: ## Environment: Set active environment to .env.local
	@echo "==> Setting active environment to .env.local"
	@ln -sf .env.local .env

env-staging: ## Environment: Set active environment to .env.staging
	@echo "==> Setting active environment to .env.staging"
	@if [ ! -f ".env.staging" ]; then echo "  ✗ .env.staging not found. Create it from .env.example"; exit 1; fi
	@ln -sf .env.staging .env

migrate: ## Environment: Run database migrations
	@$(MAKE) env-check
	@echo "==> Running migrations..."
	bun run db:migrate

# --- Development ---

dev: ## Development: Start the local development stack (native)
	@$(MAKE) env-check
	bun run dev

# --- Quality ---

test: ## Quality: Run unit and integration tests
	@$(MAKE) env-check
	bun run test

fmt: ## Quality: Apply rustfmt to the workspace
	@echo "==> Running cargo fmt --all..."
	cargo fmt --all

fmt-check: ## Quality: Check rustfmt is clean (CI parity — `cargo fmt --all -- --check`)
	@echo "==> Checking formatting (CI parity)..."
	cargo fmt --all -- --check

clippy: ## Quality: Run clippy with the same flags CI uses (workspace, all targets/features, -D warnings)
	@echo "==> Running clippy (CI parity)..."
	cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated

ci-fast: ## Quality: Fast CI parity — fmt-check + clippy only (no test, no Docker). Used by the pre-push hook.
	@$(MAKE) fmt-check
	@$(MAKE) clippy

ci: ## Quality: Run every gate CI runs locally — fmt-check, clippy, test. Use before `git push`.
	@$(MAKE) fmt-check
	@$(MAKE) clippy
	@$(MAKE) test

install-hooks: ## Setup: Enable the .githooks/ pre-push hook (runs `make ci-fast` on every git push)
	@echo "==> Installing .githooks/ as the git-hooks path..."
	@git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true
	@echo "  ✓ pre-push hook active. Bypass once with \`git push --no-verify\`; uninstall with \`git config --unset core.hooksPath\`."

# --- Docker ---

docker-build: ## Docker: Build the docker images
	@$(MAKE) env-check
	@echo "==> Building Docker images..."
	docker compose build

docker-up: ## Docker: Start the services via docker-compose
	@$(MAKE) env-check
	@echo "==> Starting Keycast stack..."
	docker compose up -d

docker-down: ## Docker: Stop the services
	@$(MAKE) env-check
	@echo "==> Stopping Keycast stack..."
	docker compose down

docker-logs: ## Docker: Follow docker logs
	@$(MAKE) env-check
	docker compose logs -f

# Support-admin Redis-set helpers. Mostly bootstrap escape hatches —
# after the first grant lands in the AOF-backed `redis_data` volume, the
# Operations → Users page in systemtools is the right path for
# subsequent grants. These recipes stay for the bootstrap case (fresh
# Redis container, no existing support-admin to use the UI as).
# PUBKEY is required and must be a 64-char lowercase hex string — the
# raw `SADD` doesn't resolve npub / email like the HTTP endpoint does,
# so passing the wrong shape would corrupt the set silently.

support-admin-grant: ## Docker: Grant support-admin to PUBKEY=<hex>. Persists via AOF.
	@if [ -z "$(PUBKEY)" ]; then echo "  ✗ PUBKEY=<64-char hex> required"; exit 1; fi
	@echo "$(PUBKEY)" | grep -Eq '^[0-9a-f]{64}$$' || (echo "  ✗ PUBKEY must be 64 lowercase hex chars"; exit 1)
	@echo "==> SADD support_admins $(PUBKEY)..."
	@docker exec keycast-redis redis-cli SADD support_admins $(PUBKEY)
	@echo "  ✓ Granted. Verify: make support-admin-list"

support-admin-revoke: ## Docker: Revoke support-admin from PUBKEY=<hex>.
	@if [ -z "$(PUBKEY)" ]; then echo "  ✗ PUBKEY=<64-char hex> required"; exit 1; fi
	@echo "$(PUBKEY)" | grep -Eq '^[0-9a-f]{64}$$' || (echo "  ✗ PUBKEY must be 64 lowercase hex chars"; exit 1)
	@echo "==> SREM support_admins $(PUBKEY)..."
	@docker exec keycast-redis redis-cli SREM support_admins $(PUBKEY)
	@echo "  ✓ Revoked."

support-admin-list: ## Docker: List the current support-admin pubkeys (Redis SMEMBERS support_admins).
	@docker exec keycast-redis redis-cli SMEMBERS support_admins

# --- Internal ---

env-check:
	@if [ ! -L ".env" ] && [ ! -f ".env" ]; then echo "  ✗ No .env file or symlink found. Run 'make setup'"; exit 1; fi
