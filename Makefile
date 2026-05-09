.PHONY: build run lint fmt test clean generate templ help

BINARY  := bin/agentsmith
CONFIG  := config.yaml
GO      := go

## generate: regenerate templ-produced files (only needed when editing *.templ)
generate:
	$(GO) run github.com/a-h/templ/cmd/templ@latest generate ./internal/admin/ui/

## templ: alias for generate (kept for muscle memory)
templ: generate

## build: compile the binary into bin/ (uses committed *_templ.go files)
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
