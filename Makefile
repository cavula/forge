SHELL := /bin/sh
TOOLS := $(CURDIR)/.tools
export PATH := $(TOOLS):$(PATH)
COMPOSE := docker compose -f deploy/compose/compose.yaml
PNPM := pnpm
DATABASE_URL ?= postgres://forge_owner:forge-owner-dev-only@localhost:5432/forge?sslmode=disable
TEST_DATABASE_URL ?= postgres://forge_app:forge-dev-only@localhost:5432/forge?sslmode=disable
TEST_BOOTSTRAP_OWNER_DATABASE_URL ?= $(DATABASE_URL)
.PHONY: dev down tools generate lint test integration build check breaking migrate smoke web-install

dev:
	$(COMPOSE) up --build -d --wait --wait-timeout 300
	$(MAKE) smoke

down:
	$(COMPOSE) down

smoke:
	curl --fail --silent --show-error --retry 30 --retry-connrefused --retry-delay 2 -o /dev/null http://localhost:8080/readyz
	curl --fail --silent --show-error http://localhost:8080/forge.v1.FoundationService/GetInfo -H 'Content-Type: application/json' -d '{}'
	curl --fail --silent --show-error --retry 30 --retry-connrefused --retry-delay 2 -o /dev/null http://localhost:3000

tools:
	GOBIN=$(TOOLS) go install github.com/bufbuild/buf/cmd/buf@v1.74.0
	GOBIN=$(TOOLS) go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	sh scripts/install-opa.sh "$(TOOLS)/opa"

web-install:
	$(PNPM) --dir web install --frozen-lockfile

generate:
	buf generate

lint:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	buf lint
	buf format --diff --exit-code
	opa check --strict policies
	$(PNPM) --dir web lint

test:
	go test -race -coverprofile=coverage.out ./...
	$(PNPM) --dir web test
	opa test --coverage --threshold=70 policies > policy-coverage.json

integration:
	TEST_DATABASE_URL='$(TEST_DATABASE_URL)' TEST_BOOTSTRAP_OWNER_DATABASE_URL='$(TEST_BOOTSTRAP_OWNER_DATABASE_URL)' go test -race -count=1 -v ./internal/database ./internal/auth ./internal/orgs

migrate:
	DATABASE_URL='$(DATABASE_URL)' go run ./cmd/migrate

build:
	go build ./cmd/...
	$(PNPM) --dir web build

breaking:
	./scripts/buf-breaking.sh

check: generate lint test build breaking
	govulncheck ./...
