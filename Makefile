GO ?= go
BIN := bin/ldapact
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
SOURCES := $(shell find cmd pkg -type f -name '*.go' ! -name '*_test.go')
# This repo sits under a parent go.work that does not list it; build standalone.
GOWORK ?= off
export GOWORK

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build dist test test-integration test-js lint fmt vet staticcheck govulncheck run clean

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
	rm -rf dist
