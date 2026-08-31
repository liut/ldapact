GO ?= go
BIN := bin/ldapact
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
SOURCES := $(shell find cmd pkg -type f -name '*.go' ! -name '*_test.go')
# Lint tool versions; pin with STATICCHECK_VERSION / GOVULNCHECK_VERSION.
STATICCHECK_VERSION ?= latest
GOVULNCHECK_VERSION ?= latest
# This repo sits under a parent go.work that does not list it; build standalone.
GOWORK ?= off
export GOWORK

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build dist test test-integration test-js lint tools fmt vet staticcheck govulncheck run clean

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
	go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

lint: fmt vet staticcheck govulncheck

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

staticcheck:
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed — run: make tools"; exit 1; fi

govulncheck:
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed — run: make tools (skipping)"; fi

run:
	$(GO) run ./cmd/ldapact

clean:
	rm -f $(BIN)
	rm -rf dist
