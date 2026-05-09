.PHONY: build run lint fmt clean help

BINARY   := agentsmith
GO       := go
GOFLAGS  :=

## build: compile the binary
build:
	$(GO) build $(GOFLAGS) -o $(BINARY) .

## run: build and start agentsmith (requires agentsmith.env and config.yaml)
run: build
	./run.sh

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## fmt: format all Go source files
fmt:
	golangci-lint fmt ./...

## test: run tests
test:
	$(GO) test ./...

## clean: remove build artefacts and debugger binaries
clean:
	rm -f $(BINARY)
	rm -f __debug_bin*

## help: list available targets
help:
	@grep -E '^##' Makefile | sed 's/## //'
