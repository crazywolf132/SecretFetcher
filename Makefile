.PHONY: all build test lint clean install-tools

GO := go
GOFLAGS := -v
BINARY_NAME := secretfetch
COVERAGE_FILE := coverage.out

all: lint test build

build:
	$(GO) build $(GOFLAGS) ./...

test:
	$(GO) test $(GOFLAGS) -race -coverprofile=$(COVERAGE_FILE) ./...
	$(GO) tool cover -func=$(COVERAGE_FILE)

lint: install-tools
	revive -config revive.toml ./...
	$(GO) vet ./...

clean:
	$(GO) clean
	rm -f $(COVERAGE_FILE)
	rm -f $(BINARY_NAME)

install-tools:
	@which revive > /dev/null || $(GO) install github.com/mgechev/revive@latest

.DEFAULT_GOAL := all
