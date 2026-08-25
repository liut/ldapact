GO ?= go
BIN := bin/ldapact
VERSION ?= dev
# This repo sits under a parent go.work that does not list it; build standalone.
GOWORK ?= off
export GOWORK

.PHONY: build test lint fmt vet staticcheck run clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) -ldflags "-X main.version=$(VERSION)" ./cmd/ldapact

test:
	$(GO) test ./...

lint: fmt vet staticcheck

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

staticcheck:
	staticcheck ./...

run:
	$(GO) run ./cmd/ldapact -config config/example.yaml

clean:
	rm -f $(BIN)
