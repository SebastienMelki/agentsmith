package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/config"
	"github.com/sebastienmelki/agentsmith/internal/gateway"
	"github.com/sebastienmelki/agentsmith/internal/identity"
)

// newReq builds a context-aware GET request for the given path. Tests pass
// no body, so this trivial wrapper keeps the noctx linter happy without
// repeating context boilerplate at every call site.
func newReq(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

// fakeGateway implements gatewaySource for tests, sidestepping the need to
// stand up real backends.
type fakeGateway struct {
	backends []gateway.BackendStatus
	details  map[string]gateway.BackendDetail
}

func (f *fakeGateway) Backends() []gateway.BackendStatus {
	return f.backends
}

func (f *fakeGateway) BackendDetails() []gateway.BackendDetail {
	out := make([]gateway.BackendDetail, len(f.backends))
	for i, s := range f.backends {
		out[i] = gateway.BackendDetail{BackendStatus: s}
	}
	return out
}

func (f *fakeGateway) BackendByName(name string) (gateway.BackendDetail, bool) {
	d, ok := f.details[name]
	return d, ok
}

func (f *fakeGateway) AggregateMetrics() gateway.Metrics {
	return gateway.Metrics{}
}

func (f *fakeGateway) SubscribeLogs(_ string) (ch chan gateway.CallEntry, unsub func(), ok bool) {
	return nil, nil, false
}

func newServer(fg *fakeGateway) http.Handler {
	return (&Server{gw: fg}).Handler()
}

func TestHealthz_OKWhenAtLeastOneBackendConnected(t *testing.T) {
	now := time.Now()
	fg := &fakeGateway{backends: []gateway.BackendStatus{
		{Name: "alpha", State: gateway.StateConnected, LastConnectedAt: &now},
		{Name: "beta", State: gateway.StateError, LastError: "boom"},
	}}
	rr := httptest.NewRecorder()
	newServer(fg).ServeHTTP(rr, newReq(t, "/healthz"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Status            string `json:"status"`
		ConnectedBackends int    `json:"connectedBackends"`
		TotalBackends     int    `json:"totalBackends"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" || body.ConnectedBackends != 1 || body.TotalBackends != 2 {
		t.Errorf("body = %+v", body)
	}
}

func TestHealthz_DegradedWhenNoBackendConnected(t *testing.T) {
	fg := &fakeGateway{backends: []gateway.BackendStatus{
		{Name: "alpha", State: gateway.StateConnecting},
	}}
	rr := httptest.NewRecorder()
	newServer(fg).ServeHTTP(rr, newReq(t, "/healthz"))

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"degraded"`) {
		t.Errorf("body did not contain degraded status: %s", rr.Body.String())
	}
}

func TestBackends_ReturnsJSONArray(t *testing.T) {
	fg := &fakeGateway{backends: []gateway.BackendStatus{
		{Name: "alpha", URL: "http://a", State: gateway.StateConnected, ToolCount: 3},
		{Name: "beta", URL: "http://b", State: gateway.StateError, LastError: "x"},
	}}
	rr := httptest.NewRecorder()
	newServer(fg).ServeHTTP(rr, newReq(t, "/backends"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var got []gateway.BackendStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Name != "alpha" || got[1].Name != "beta" {
		t.Errorf("decoded = %+v", got)
	}
}

func TestBackendDetail_404WhenUnknown(t *testing.T) {
	fg := &fakeGateway{details: map[string]gateway.BackendDetail{}}
	rr := httptest.NewRecorder()
	newServer(fg).ServeHTTP(rr, newReq(t, "/ui/backends/missing"))

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestBackendDetailPartial_404WhenUnknown(t *testing.T) {
	fg := &fakeGateway{details: map[string]gateway.BackendDetail{}}
	rr := httptest.NewRecorder()
	newServer(fg).ServeHTTP(rr, newReq(t, "/ui/backends/missing/partial"))

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestUserMutations_RefusedInUnprotectedMode pins the symmetry between
// POST /users and DELETE /users/{id}: both are user-record operations that
// only make sense in protected mode, and both must refuse with 403 outside
// it. Before round-2 cleanup, DELETE silently passed through and returned
// 204 even in unprotected mode.
func TestUserMutations_RefusedInUnprotectedMode(t *testing.T) {
	fg := &fakeGateway{}
	srv := &Server{gw: fg, users: identity.NewMemoryStore(), authMode: config.ModeUnprotected}
	h := srv.Handler()

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"POST /users", http.MethodPost, "/users"},
		{"DELETE /users/alice", http.MethodDelete, "/users/alice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), c.method, c.path, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s status = %d, want 403; body=%s", c.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestDashboard_RendersHTML(t *testing.T) {
	fg := &fakeGateway{backends: []gateway.BackendStatus{
		{Name: "alpha", State: gateway.StateConnected},
	}}
	rr := httptest.NewRecorder()
	newServer(fg).ServeHTTP(rr, newReq(t, "/"))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alpha") {
		t.Errorf("dashboard body did not include backend name; got:\n%s", body)
	}
}
