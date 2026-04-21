# ─────────────────────────────────────────────────────────────────────────────
# Keycast Development Helper
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: check-prereq install-prereq setup migrate help dev

help:
	@echo "Synvya Keycast Development Helper"
	@echo ""
	@echo "Available targets:"
	@echo "  check-prereq    - Verify Rust, Bun, and SQLX are installed"
	@echo "  install-prereq  - Install sqlx-cli tool (required for migrations)"
	@echo "  setup           - Initialize .env and generate master key"
	@echo "  migrate         - Run database migrations"
	@echo "  dev             - Start the local development stack (native)"
	@echo "  docker-build    - Build the docker images"
	@echo "  docker-up       - Start the services via docker-compose"
	@echo "  docker-down     - Stop the services"
	@echo "  docker-logs     - Follow docker logs"

check-prereq:
	@echo "==> Checking Keycast prerequisites..."
	@command -v cargo >/dev/null 2>&1 || (echo "  ✗ cargo (Rust) not found"; exit 1)
	@command -v bun >/dev/null 2>&1 || (echo "  ✗ bun not found"; exit 1)
	@command -v sqlx >/dev/null 2>&1 || (echo "  ✗ sqlx-cli not found. Run 'make install-prereq'"; exit 1)
	@echo "  ✓ All Keycast prerequisites met!"

install-prereq:
	@echo "==> Installing prerequisites..."
	cargo install sqlx-cli --no-default-features --features postgres
	cargo install cargo-nextest --locked

setup:
	@echo "==> Initializing environment configuration (.env.local)..."
	@if [ ! -f ".env.local" ]; then bash scripts/init.sh --domain localhost --file .env.local; fi
	@if grep -q "SERVER_NSEC=$$" .env.local; then \
		echo "==> Generating SERVER_NSEC for .env.local..."; \
		RAND_SEC=$$(openssl rand -hex 32); \
		sed -i '' "s/SERVER_NSEC=.*/SERVER_NSEC=$$RAND_SEC/" .env.local || sed -i "s/SERVER_NSEC=.*/SERVER_NSEC=$$RAND_SEC/" .env.local; \
	fi
	@if [ ! -f "master.key" ]; then bun run key:generate; fi
	@$(MAKE) env-local
	@echo "  ✓ Setup complete."

# Environment switching targets
env-local:
	@echo "==> Setting active environment to .env.local"
	@ln -sf .env.local .env

env-staging:
	@echo "==> Setting active environment to .env.staging"
	@if [ ! -f ".env.staging" ]; then echo "  ✗ .env.staging not found. Create it from .env.example"; exit 1; fi
	@ln -sf .env.staging .env

migrate:
	@$(MAKE) env-check
	@echo "==> Running migrations..."
	bun run db:migrate

dev:
	@$(MAKE) env-check
	bun run dev

env-check:
	@if [ ! -L ".env" ] && [ ! -f ".env" ]; then echo "  ✗ No .env file or symlink found. Run 'make setup'"; exit 1; fi

docker-build:
	@$(MAKE) env-check
	@echo "==> Building Docker images..."
	docker compose build

docker-up:
	@$(MAKE) env-check
	@echo "==> Starting Keycast stack..."
	docker compose up -d

docker-down:
	@$(MAKE) env-check
	@echo "==> Stopping Keycast stack..."
	docker compose down

docker-logs:
	@$(MAKE) env-check
	docker compose logs -f

test:
	@$(MAKE) env-check
	bun run test
