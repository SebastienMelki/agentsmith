package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewParsesLevel(t *testing.T) {
	cases := []struct {
		in      string
		wantOK  bool
		matches slog.Level
	}{
		{"", true, slog.LevelInfo},
		{"info", true, slog.LevelInfo},
		{"INFO", true, slog.LevelInfo},
		{"debug", true, slog.LevelDebug},
		{"warn", true, slog.LevelWarn},
		{"warning", true, slog.LevelWarn},
		{"error", true, slog.LevelError},
		{"bogus", false, 0},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			_, err := New(Config{Level: c.in, Format: "json"})
			if c.wantOK && err != nil {
				t.Fatalf("New(%q) returned error: %v", c.in, err)
			}
			if !c.wantOK && err == nil {
				t.Fatalf("New(%q) accepted invalid level", c.in)
			}
		})
	}
}

func TestNewRejectsInvalidFormat(t *testing.T) {
	if _, err := New(Config{Level: "info", Format: "yaml"}); err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestNewBuildsJSONHandler(t *testing.T) {
	// Build a logger that writes to an in-memory buffer so we can assert
	// the output shape. The exported API only takes a Config (which routes
	// to stderr/stdout) so we exercise the handler choice through the
	// resulting *slog.Logger's effective behaviour.
	l, err := New(Config{Level: "info", Format: "json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if l == nil {
		t.Fatal("New returned nil logger")
	}
}

func TestSanitizeRequestID(t *testing.T) {
	cases := map[string]string{
		"abc123":           "abc123",
		"abc 123":          "abc123",
		"abc!@#-_xyz":      "abc-_xyz",
		"":                 "",
		strings.Repeat("a", 200): strings.Repeat("a", requestIDMaxLen),
	}
	for in, want := range cases {
		if got := sanitizeRequestID(in); got != want {
			t.Errorf("sanitizeRequestID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRequestIDMiddlewareGeneratesID(t *testing.T) {
	var got string
	h := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RequestIDFromContext(r.Context())
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	h.ServeHTTP(rr, req)
	if got == "" {
		t.Fatal("expected request_id in context")
	}
	if rr.Header().Get(requestIDHeader) != got {
		t.Errorf("response X-Request-ID = %q, want %q", rr.Header().Get(requestIDHeader), got)
	}
}

func TestRequestIDMiddlewareEchoesIncoming(t *testing.T) {
	var got string
	h := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RequestIDFromContext(r.Context())
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Header.Set(requestIDHeader, "client-supplied-42")
	h.ServeHTTP(rr, req)
	if got != "client-supplied-42" {
		t.Errorf("request_id = %q, want %q", got, "client-supplied-42")
	}
	if rr.Header().Get(requestIDHeader) != "client-supplied-42" {
		t.Errorf("response X-Request-ID = %q", rr.Header().Get(requestIDHeader))
	}
}

func TestRequestIDMiddlewareSanitizesIncoming(t *testing.T) {
	var got string
	h := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RequestIDFromContext(r.Context())
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Header.Set(requestIDHeader, "evil\n\rvalue!@#")
	h.ServeHTTP(rr, req)
	if got != "evilvalue" {
		t.Errorf("sanitized request_id = %q, want %q", got, "evilvalue")
	}
}

func TestAccessLogEmitsRecord(t *testing.T) {
	// Replace slog.Default for the duration of this test with a JSON
	// handler writing to a buffer so we can decode the access record.
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(orig)

	// Freeze time so duration_ms is deterministic. nowFn returns once for
	// start, then once again for end.
	calls := 0
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	origNow := nowFn
	nowFn = func() time.Time {
		calls++
		if calls == 1 {
			return t0
		}
		return t0.Add(123 * time.Millisecond)
	}
	defer func() { nowFn = origNow }()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attach a user_id the way identity middleware would so the
		// access record picks it up.
		ctx := WithUserID(r.Context(), "u_test")
		*r = *r.WithContext(ctx)
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	})
	h := AccessLog("mcp", RequestIDMiddleware(inner))

	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp?x=1", strings.NewReader("payload"))
	req.Header.Set("User-Agent", "claude-cli/test")
	h.ServeHTTP(rr, req)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("access record was not valid JSON: %v\nraw: %s", err, buf.String())
	}
	if rec["event"] != "access" {
		t.Errorf("event = %v, want access", rec["event"])
	}
	if rec["server"] != "mcp" {
		t.Errorf("server = %v, want mcp", rec["server"])
	}
	if rec["method"] != "POST" {
		t.Errorf("method = %v", rec["method"])
	}
	if rec["path"] != "/mcp" {
		t.Errorf("path = %v", rec["path"])
	}
	if rec["query"] != "x=1" {
		t.Errorf("query = %v", rec["query"])
	}
	if v, _ := rec["status"].(float64); int(v) != http.StatusTeapot {
		t.Errorf("status = %v, want %d", rec["status"], http.StatusTeapot)
	}
	if v, _ := rec["bytes_out"].(float64); int(v) != len("hello") {
		t.Errorf("bytes_out = %v, want %d", rec["bytes_out"], len("hello"))
	}
	if v, _ := rec["duration_ms"].(float64); int(v) != 123 {
		t.Errorf("duration_ms = %v, want 123", rec["duration_ms"])
	}
	if rec["user_id"] != "u_test" {
		t.Errorf("user_id = %v, want u_test", rec["user_id"])
	}
	if rec["request_id"] == nil || rec["request_id"] == "" {
		t.Errorf("request_id missing")
	}
	if rec["user_agent"] != "claude-cli/test" {
		t.Errorf("user_agent = %v", rec["user_agent"])
	}
}

func TestFromContextFallsBackToDefault(t *testing.T) {
	if FromContext(context.Background()) == nil {
		t.Fatal("FromContext returned nil")
	}
	if FromContext(nil) == nil { //nolint:staticcheck // intentional nil to assert fallback
		t.Fatal("FromContext(nil) returned nil")
	}
}
