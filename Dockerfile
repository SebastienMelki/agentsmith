# syntax=docker/dockerfile:1.7

# ─── build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/agentsmith \
        .

# ─── runtime stage ────────────────────────────────────────────────────────────
# distroless/static is ~2 MB, has no shell, no package manager, and ships
# /etc/passwd with a `nonroot` user (UID 65532). The final image is the
# Go binary plus that base — typically ~17–20 MB.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="agentsmith" \
      org.opencontainers.image.description="Lightweight MCP federation gateway" \
      org.opencontainers.image.source="https://github.com/sebastienmelki/agentsmith" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/agentsmith /agentsmith

# 3001 = MCP endpoint, 3002 = admin UI.
EXPOSE 3001 3002

USER nonroot:nonroot
ENTRYPOINT ["/agentsmith"]
CMD ["-f", "/etc/agentsmith/config.yaml"]
