package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// doGet issues a GET against url using the supplied client and discards the body.
// Wrapped in a helper so each test stays focused on the assertion, not the
// boilerplate of building a context-aware request.
func doGet(t *testing.T, client *http.Client, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Do: %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func TestSplitNamespacedTool(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantTarget  string
		wantTool    string
		wantOK      bool
	}{
		{"basic", "dodo__create_payment", "dodo", "create_payment", true},
		{"tool with double underscore in name", "dodo__weird__name", "dodo", "weird__name", true},
		{"no separator", "raw_tool", "", "raw_tool", false},
		{"empty", "", "", "", false},
		{"separator only", "__", "", "", true},
		{"leading separator", "__tool", "", "tool", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target, tool, ok := SplitNamespacedTool(c.in)
			if target != c.wantTarget || tool != c.wantTool || ok != c.wantOK {
				t.Errorf("SplitNamespacedTool(%q) = (%q, %q, %v); want (%q, %q, %v)",
					c.in, target, tool, ok, c.wantTarget, c.wantTool, c.wantOK)
			}
		})
	}
}

// recordingServer captures the headers of every incoming request, protected
// by a mutex so concurrent requests don't race the slice.
type recordingServer struct {
	mu      sync.Mutex
	headers []http.Header
}

func (r *recordingServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		// Clone so later mutations to req don't affect captured headers.
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}
}

func (r *recordingServer) seenHeader(key, value string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range r.headers {
		if slices.Contains(h.Values(key), value) {
			return true
		}
	}
	return false
}

// TestHeaderInjector_OnlyConfiguredHeadersAreSet validates the unit primitive
// that enforces per-backend credential isolation. If this contract breaks,
// agentsmith's central security claim breaks.
func TestHeaderInjector_OnlyConfiguredHeadersAreSet(t *testing.T) {
	srv := &recordingServer{}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	injector := &headerInjector{
		base: http.DefaultTransport,
		headers: map[string]string{
			"X-Backend-Token": "alpha-secret",
			"X-Tenant":        "alpha",
		},
	}
	client := &http.Client{Transport: injector}

	doGet(t, client, ts.URL)

	if !srv.seenHeader("X-Backend-Token", "alpha-secret") {
		t.Error("configured header was not injected")
	}
	if !srv.seenHeader("X-Tenant", "alpha") {
		t.Error("second configured header was not injected")
	}
	if srv.seenHeader("X-Other-Token", "anything") {
		t.Error("unconfigured header leaked into request")
	}
}

// TestHeaderInjector_PerBackendIsolation is the marquee security test:
// two backends, each with a distinct injector, must not see each other's
// headers under any circumstance — including when both clients fire requests
// concurrently.
func TestHeaderInjector_PerBackendIsolation(t *testing.T) {
	alpha := &recordingServer{}
	beta := &recordingServer{}
	alphaSrv := httptest.NewServer(alpha.handler())
	defer alphaSrv.Close()
	betaSrv := httptest.NewServer(beta.handler())
	defer betaSrv.Close()

	alphaClient := &http.Client{Transport: &headerInjector{
		base:    http.DefaultTransport,
		headers: map[string]string{"X-Alpha-Token": "alpha-secret"},
	}}
	betaClient := &http.Client{Transport: &headerInjector{
		base:    http.DefaultTransport,
		headers: map[string]string{"X-Beta-Token": "beta-secret"},
	}}

	const requestsPerClient = 25
	var wg sync.WaitGroup
	wg.Add(2 * requestsPerClient)
	for range requestsPerClient {
		go func() {
			defer wg.Done()
			doGet(t, alphaClient, alphaSrv.URL)
		}()
		go func() {
			defer wg.Done()
			doGet(t, betaClient, betaSrv.URL)
		}()
	}
	wg.Wait()

	// Each backend must see ONLY its own header.
	if !alpha.seenHeader("X-Alpha-Token", "alpha-secret") {
		t.Error("alpha backend never saw its own token")
	}
	if alpha.seenHeader("X-Beta-Token", "beta-secret") {
		t.Error("beta token leaked into alpha backend — credential isolation broken")
	}

	if !beta.seenHeader("X-Beta-Token", "beta-secret") {
		t.Error("beta backend never saw its own token")
	}
	if beta.seenHeader("X-Alpha-Token", "alpha-secret") {
		t.Error("alpha token leaked into beta backend — credential isolation broken")
	}
}

// TestHeaderInjector_NoHeadersConfigured ensures a backend with no headers
// produces a request with no injected auth, even when other backends do.
func TestHeaderInjector_NoHeadersConfigured(t *testing.T) {
	srv := &recordingServer{}
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	client := &http.Client{Transport: &headerInjector{
		base:    http.DefaultTransport,
		headers: nil,
	}}
	doGet(t, client, ts.URL)

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.headers) != 1 {
		t.Fatalf("got %d requests, want 1", len(srv.headers))
	}
	for k := range srv.headers[0] {
		if strings.HasPrefix(k, "X-") {
			t.Errorf("unexpected X-prefixed header set: %s", k)
		}
	}
}
