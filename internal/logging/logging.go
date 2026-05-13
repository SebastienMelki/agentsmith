// Package logging builds the agentsmith root logger and provides HTTP
// middleware (request-ID propagation, access logging) plus a context-scoped
// logger that downstream handlers can enrich with per-request fields.
//
// The package stays on stdlib log/slog so the rest of the codebase can keep
// calling slog.Info/Warn/Error against the package-global default. The
// middleware-attached logger is opt-in via FromContext where request
// correlation matters.
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config describes how the root logger should be built. Zero values resolve to
// the production defaults: info level, json format, stderr destination.
type Config struct {
	Level  string
	Format string
	Output string // "stderr" (default) | "stdout" | path — v1 only honours the first two
}

// New builds a *slog.Logger from cfg. Returns an error if level or format are
// invalid; unknown Output falls back to stderr.
func New(cfg Config) (*slog.Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	dest, err := resolveOutput(cfg.Output)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "", "json":
		handler = slog.NewJSONHandler(dest, opts)
	case "text":
		handler = slog.NewTextHandler(dest, opts)
	default:
		return nil, fmt.Errorf("logging: invalid format %q (expected text or json)", cfg.Format)
	}
	return slog.New(handler), nil
}

// parseLevel accepts debug/info/warn/error case-insensitively. Empty defaults
// to info so an unset YAML field doesn't break startup.
func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: invalid level %q (expected debug, info, warn, or error)", s)
	}
}

// resolveOutput maps an Output string to a writer. Only stderr/stdout are
// supported in v1; the field exists so future file/socket sinks can be added
// without churning callers.
func resolveOutput(s string) (io.Writer, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "stderr":
		return os.Stderr, nil
	case "stdout":
		return os.Stdout, nil
	default:
		return nil, fmt.Errorf("logging: unsupported output %q (expected stderr or stdout)", s)
	}
}

type ctxKey struct{}

// WithLogger returns a child context carrying l. Handlers that pull from
// FromContext will see this logger instead of slog.Default().
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the logger attached by middleware, falling back to
// slog.Default() so callers never need a nil check.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

const (
	requestIDHeader = "X-Request-ID"
	// requestIDMaxLen caps how much of a client-supplied X-Request-ID we
	// echo. Long-enough to be useful, short-enough to fit one line and to
	// stop a hostile caller from filling log records with garbage.
	requestIDMaxLen = 64
)

// NewRequestID returns a 16-hex-char identifier from crypto/rand. Short enough
// to read in a terminal, long enough to be unique across a deployment.
func NewRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failures are typically fatal at the OS level; if we
		// somehow recover, an empty string is still a valid "no id" signal
		// for downstream code.
		return ""
	}
	return hex.EncodeToString(b[:])
}

// RequestIDFromContext returns the request_id attached by RequestIDMiddleware,
// or "" when no middleware has run.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(reqIDKey{}).(string); ok {
		return id
	}
	return ""
}

type reqIDKey struct{}

// RequestIDMiddleware attaches a per-request ID to the context and echoes it
// on the X-Request-ID response header. A caller-supplied X-Request-ID is
// preserved (sanitized and length-capped) so correlation IDs survive across
// proxy hops; otherwise a fresh ID is generated.
//
// The new context is installed by mutating *r in place (rather than the
// usual next.ServeHTTP(w, r.WithContext(ctx)) idiom) so middleware sitting
// further OUT in the chain — notably AccessLog, which reads r.Context()
// after next returns — can observe values added here. All other agentsmith
// middleware follows the same in-place pattern for the same reason.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeRequestID(r.Header.Get(requestIDHeader))
		if id == "" {
			id = NewRequestID()
		}
		w.Header().Set(requestIDHeader, id)
		ctx := context.WithValue(r.Context(), reqIDKey{}, id)
		ctx = WithLogger(ctx, FromContext(ctx).With("request_id", id))
		*r = *r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// sanitizeRequestID strips any byte that isn't a printable ASCII rune in the
// safe set [A-Za-z0-9_-]. Returning "" forces the middleware to generate a
// fresh ID rather than echo a malformed header value into logs.
func sanitizeRequestID(s string) string {
	if len(s) > requestIDMaxLen {
		s = s[:requestIDMaxLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// AccessLog wraps next and emits one Info-level access record per request
// using the package-global slog default. server is a label (typically "mcp"
// or "admin") embedded in every record so a single grep can separate gateway
// from admin traffic. Callers decide whether to install this middleware at
// all — there's no in-middleware on/off toggle.
func AccessLog(server string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := nowFn()
		rw := newAccessWriter(w)
		next.ServeHTTP(rw, r)

		attrs := []any{
			"event", "access",
			"server", server,
			"request_id", RequestIDFromContext(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", nowFn().Sub(start).Milliseconds(),
			"bytes_out", rw.bytesWritten,
			"remote_addr", r.RemoteAddr,
			"proto", r.Proto,
		}
		if r.URL.RawQuery != "" {
			attrs = append(attrs, "query", r.URL.RawQuery)
		}
		if r.ContentLength >= 0 {
			attrs = append(attrs, "bytes_in", r.ContentLength)
		}
		if ua := r.UserAgent(); ua != "" {
			attrs = append(attrs, "user_agent", ua)
		}
		if ref := r.Referer(); ref != "" {
			attrs = append(attrs, "referer", ref)
		}
		if uid := userIDFromContextLogger(r.Context()); uid != "" {
			attrs = append(attrs, "user_id", uid)
		}
		FromContext(r.Context()).Info("http access", attrs...)
	})
}

// userIDFromContextLogger reaches into the ctx-scoped logger to recover
// user_id when identity middleware has attached it. We can't read slog.Attr
// values back out, so we keep a parallel context key for the access log.
func userIDFromContextLogger(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if uid, ok := ctx.Value(userIDKey{}).(string); ok {
		return uid
	}
	return ""
}

type userIDKey struct{}

// WithUserID attaches the resolved user ID to the context so the access log
// middleware (which runs *after* identity but emits its record *after*
// next.ServeHTTP returns) can include it without parsing the request again.
func WithUserID(ctx context.Context, uid string) context.Context {
	return context.WithValue(ctx, userIDKey{}, uid)
}

// nowFn is replaced in tests to make duration_ms deterministic.
var nowFn = time.Now
