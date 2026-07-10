.PHONY: dev build build-web migrate seed lint test web

# Default DATABASE_URL used by migrate/seed if not already set in the environment.
DATABASE_URL ?= postgres://shellwarden:shellwarden@localhost:5432/shellwarden?sslmode=disable
export DATABASE_URL

# dev: bring up dependencies and run the gateway with live reload (Air).
dev:
	docker compose up -d postgres guacd
	@command -v air >/dev/null 2>&1 || go install github.com/air-verse/air@latest
	air -c .air.toml || go run ./cmd/gateway

# build: compile gateway and agent binaries into ./bin
build:
	mkdir -p bin
	go build -o bin/gateway ./cmd/gateway
	go build -o bin/agent ./cmd/agent

# migrate: apply SQL migrations against $DATABASE_URL.
# The gateway also runs migrations on startup; this target is for manual runs.
migrate:
	@for f in internal/db/migrations/*.sql; do \
		echo "applying $$f"; \
		psql "$(DATABASE_URL)" -f "$$f"; \
	done

# seed: insert the default admin user (admin / changeme).
# The hash is a bcrypt hash of "changeme". Each '$' is written as '\$$' so make
# leaves a literal '$' and the shell (inside double quotes) does not expand it.
seed:
	psql "$(DATABASE_URL)" -c "INSERT INTO users (username, password_hash, role) VALUES ('admin', '\$$2a\$$10\$$UaAjfrnx4ExDC41wuzERJebw9HZW2SCSMW5H9cu1MQdD5AU3thQti', 'admin') ON CONFLICT (username) DO NOTHING;"

lint:
	golangci-lint run ./...

test:
	go test ./...

# test-e2e: bring up the self-contained stack and run the full e2e suite.
TEST_COMPOSE = docker compose -f docker-compose.test.yml
test-e2e:
	$(TEST_COMPOSE) up --build -d
	@echo "waiting for target to self-enroll + come online..."
	@sleep 25
	PSQL="$(TEST_COMPOSE) exec -T postgres psql -U shellwarden -d shellwarden" ./scripts/e2e_test.sh

test-e2e-down:
	$(TEST_COMPOSE) down -v

# web: install deps and start the Vite dev server.
web:
	cd web && npm install && npm run dev

# build-web: produce the production SPA build into ./static
build-web:
	cd web && npm install && npm run build
