package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sebastienmelki/agentsmith/internal/config"
)

func TestMemoryStore_CreateAndLookup(t *testing.T) {
	s := NewMemoryStore()
	u, key, err := s.Create("alice@acme.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID != "alice@acme.com" || u.Email != "alice@acme.com" {
		t.Errorf("user = %+v", u)
	}
	if !strings.HasPrefix(key, "sk_") || len(key) < 32 {
		t.Errorf("api key looks wrong: %q", key)
	}

	got, err := s.Lookup(key)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("looked-up id = %q, want %q", got.ID, u.ID)
	}
}

func TestMemoryStore_LookupUnknownIsNotFound(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Lookup("sk_does_not_exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemoryStore_LookupEmptyIsNotFound(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Lookup("")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemoryStore_KeysAreHashedAtRest(t *testing.T) {
	// Direct inspection of the byHash map: no plaintext key should ever be a
	// value or key in there. This is what protects against an in-memory snapshot
	// (or future SQLite dump) leaking usable credentials.
	s := NewMemoryStore()
	_, key, err := s.Create("alice@acme.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for h, id := range s.byHash {
		if h == key {
			t.Error("plaintext key stored as map key")
		}
		if id == key {
			t.Error("plaintext key stored as map value")
		}
	}
}

func TestMemoryStore_DuplicateEmailIsError(t *testing.T) {
	s := NewMemoryStore()
	if _, _, err := s.Create("alice@acme.com"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, _, err := s.Create("alice@acme.com"); err == nil {
		t.Fatal("second Create should have errored")
	}
}

func TestMemoryStore_ReservedDefaultIDRejected(t *testing.T) {
	s := NewMemoryStore()
	if _, _, err := s.Create(DefaultUserID); err == nil {
		t.Fatal("Create with reserved DefaultUserID should have errored")
	}
}

func TestMemoryStore_ListAndDelete(t *testing.T) {
	s := NewMemoryStore()
	if _, _, err := s.Create("alice@acme.com"); err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	if _, _, err := s.Create("bob@acme.com"); err != nil {
		t.Fatalf("Create bob: %v", err)
	}

	users := s.List()
	if len(users) != 2 {
		t.Fatalf("List returned %d users, want 2", len(users))
	}

	if err := s.Delete("alice@acme.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.List()) != 1 {
		t.Errorf("after Delete len = %d, want 1", len(s.List()))
	}
	// Delete is idempotent.
	if err := s.Delete("alice@acme.com"); err != nil {
		t.Errorf("second Delete should be no-op, got %v", err)
	}
}

func TestMemoryStore_DeleteAlsoDropsKey(t *testing.T) {
	s := NewMemoryStore()
	_, key, err := s.Create("alice@acme.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete("alice@acme.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Lookup(key); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete Lookup returned %v, want ErrNotFound", err)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},          // case-insensitive scheme
		{"Bearer  abc  ", "abc"},       // trimmed
		{"Basic abc", ""},              // wrong scheme
		{"", ""},                       // empty
		{"Bearer", ""},                 // no token
	}
	for _, c := range cases {
		if got := bearerToken(c.in); got != c.want {
			t.Errorf("bearerToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMiddleware_UnprotectedAttachesDefaultUser(t *testing.T) {
	store := NewMemoryStore()
	var seen *User
	h := Middleware(config.ModeUnprotected, store)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if seen == nil || seen.ID != DefaultUserID {
		t.Errorf("user = %+v, want default", seen)
	}
}

func TestMiddleware_ProtectedRequiresBearer(t *testing.T) {
	store := NewMemoryStore()
	h := Middleware(config.ModeProtected, store)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not run on auth failure")
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("missing WWW-Authenticate Bearer header: %q", rr.Header().Get("WWW-Authenticate"))
	}
}

func TestMiddleware_ProtectedRejectsBadKey(t *testing.T) {
	store := NewMemoryStore()
	h := Middleware(config.ModeProtected, store)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not run on auth failure")
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer sk_invalid")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestMiddleware_ProtectedAttachesResolvedUser(t *testing.T) {
	store := NewMemoryStore()
	user, key, err := store.Create("alice@acme.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var seen *User
	h := Middleware(config.ModeProtected, store)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+key)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if seen == nil || seen.ID != user.ID {
		t.Errorf("user = %+v, want %+v", seen, user)
	}
}
