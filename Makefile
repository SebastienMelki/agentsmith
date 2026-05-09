.PHONY: build run lint fmt test clean help

BINARY  := bin/agentsmith
CONFIG  := config.yaml
GO      := go

## build: compile the binary into bin/
build:
	@mkdir -p bin
	$(GO) build -o $(BINARY) .

## run: build and start agentsmith (requires config.yaml — copy from examples/)
run: build
	@test -f $(CONFIG) || { echo "error: $(CONFIG) not found — copy one from examples/ and fill in your values"; exit 1; }
	./$(BINARY) -f $(CONFIG)

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
	rm -rf bin/
	rm -f __debug_bin*

## help: list available targets
help:
	@grep -E '^##' Makefile | sed 's/## //'
