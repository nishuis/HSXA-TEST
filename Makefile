# hsxa-banner-fingerprint — developer entry points.
MODULE  := hsxa-banner-fingerprint
BIN     := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.GitCommit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(DATE)

.PHONY: all build test cover fmt vet lint check acceptance docker demo run clean help

all: check build ## Format check, vet, tests, then build both binaries.

build: ## Build bfp-server and bfp-cli into bin/.
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/bfp-server ./cmd/bfp-server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/bfp-cli ./cmd/bfp-cli

test: ## Run the full test suite.
	go test ./...

cover: ## Run tests with coverage for the engine packages.
	go test -cover ./internal/...

fmt: ## List files that are not gofmt-clean.
	gofmt -l .

vet: ## Run go vet over every package.
	go vet ./...

lint: ## Run golangci-lint if it is installed.
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

check: fmt vet test ## Local quality gate (plan.md §4.2).

acceptance: ## End-to-end acceptance: start server, run CLI, diff against expectations.
	bash scripts/acceptance.sh

docker: ## Build both container images.
	docker compose build

demo: build ## Run the CLI against a locally started server.
	./$(BIN)/bfp-server & \
	sleep 1; \
	./$(BIN)/bfp-cli identify --input testdata/acceptance/input.json; \
	kill %1

run: build ## Start the server on the configured address.
	./$(BIN)/bfp-server

clean: ## Remove build output.
	rm -rf $(BIN) dist coverage.txt

help: ## List the available targets.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
