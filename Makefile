.PHONY: build run lint fmt test clean generate templ help

BINARY  := bin/agentsmith
CONFIG  := config.yaml
ENVFILE := agentsmith.env
GO      := go

# Pin the templ CLI to the version declared in go.mod so generator output
# matches the runtime library (the @latest CLI may emit symbols that older
# runtime versions don't export, breaking `make build`).
TEMPL_VERSION := $(shell awk '$$1 == "github.com/a-h/templ" {print $$2; exit}' go.mod)

## generate: regenerate templ-produced files (only needed when editing *.templ)
generate:
	$(GO) run github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION) generate ./internal/admin/ui/

## templ: alias for generate (kept for muscle memory)
templ: generate

## build: compile the binary into bin/ (uses committed *_templ.go files)
build:
	@mkdir -p bin
	$(GO) build -o $(BINARY) .

## run: build and start agentsmith (requires config.yaml — copy from examples/; auto-loads agentsmith.env if present)
run: build
	@test -f $(CONFIG) || { echo "error: $(CONFIG) not found — copy one from examples/ and fill in your values"; exit 1; }
	@if [ -f $(ENVFILE) ]; then set -a; . ./$(ENVFILE); set +a; ./$(BINARY) -f $(CONFIG); else ./$(BINARY) -f $(CONFIG); fi

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
