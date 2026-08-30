GO ?= go
BIN := bin/ldapact
VERSION ?= dev
# This repo sits under a parent go.work that does not list it; build standalone.
GOWORK ?= off
export GOWORK

.PHONY: build test test-integration test-js lint fmt vet staticcheck govulncheck run clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) -ldflags "-X main.version=$(VERSION)" ./cmd/ldapact

test:
	$(GO) test ./...

test-integration:
	$(GO) test -timeout 15m -count=1 ./test/integration/...

test-js:
	node test/js/autofill_test.js
	node test/js/tree_keys_test.js
	node test/js/edit_multi_test.js

lint: fmt vet staticcheck govulncheck

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

staticcheck:
	staticcheck ./...

govulncheck:
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed — run: go install golang.org/x/vuln/cmd/govulncheck@latest"; fi

run:
	$(GO) run ./cmd/ldapact

clean:
	rm -f $(BIN)
