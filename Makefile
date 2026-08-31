GO ?= go
BIN := bin/ldapact
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
SOURCES := $(shell find cmd pkg -type f -name '*.go' ! -name '*_test.go')
# Lint tool versions; pin with GOLANGCI_LINT_VERSION / GOVULNCHECK_VERSION.
GOLANGCI_LINT_VERSION ?= v2.13.2
GOVULNCHECK_VERSION ?= latest
# This repo sits under a parent go.work that does not list it; build standalone.
GOWORK ?= off
export GOWORK

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build dist test test-integration test-js lint tools fmt vet golangci-lint govulncheck run clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) -ldflags "$(LDFLAGS)" ./cmd/ldapact

dist/linux_amd64/ldapact: $(SOURCES)
	mkdir -p $(dir $@)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o $@ -ldflags "$(LDFLAGS)" ./cmd/ldapact

dist/darwin_amd64/ldapact: $(SOURCES)
	mkdir -p $(dir $@)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -o $@ -ldflags "$(LDFLAGS)" ./cmd/ldapact

dist/darwin_arm64/ldapact: $(SOURCES)
	mkdir -p $(dir $@)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -o $@ -ldflags "$(LDFLAGS)" ./cmd/ldapact

dist/windows_amd64/ldapact: $(SOURCES)
	mkdir -p $(dir $@)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -o $@.exe -ldflags "$(LDFLAGS)" ./cmd/ldapact

dist: dist/linux_amd64/ldapact dist/darwin_amd64/ldapact dist/darwin_arm64/ldapact dist/windows_amd64/ldapact

test:
	$(GO) test ./...

test-integration:
	$(GO) test -timeout 15m -count=1 ./test/integration/...

test-js:
	node test/js/autofill_test.js
	node test/js/tree_keys_test.js
	node test/js/edit_multi_test.js

tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

lint: fmt vet golangci-lint govulncheck

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

golangci-lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed — run: make tools"; exit 1; fi

govulncheck:
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed — run: make tools (skipping)"; fi

run:
	$(GO) run ./cmd/ldapact

clean:
	rm -f $(BIN)
	rm -rf dist
