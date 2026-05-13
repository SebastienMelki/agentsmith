package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryTokenStore_SaveGetRoundTrip(t *testing.T) {
	s := NewMemoryTokenStore()
	in := &Tokens{
		AccessToken:  "at",
		RefreshToken: "rt",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
		Scopes:       []string{"chat:write"},
	}
	if err := s.Save("alice", "slack", in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := s.Get("alice", "slack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.AccessToken != "at" || out.RefreshToken != "rt" || out.TokenType != "Bearer" {
		t.Errorf("round-trip mismatch: %+v", out)
	}
	if len(out.Scopes) != 1 || out.Scopes[0] != "chat:write" {
		t.Errorf("scopes round-trip wrong: %v", out.Scopes)
	}
}

func TestMemoryTokenStore_GetMissingIsNotFound(t *testing.T) {
	s := NewMemoryTokenStore()
	_, err := s.Get("alice", "slack")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemoryTokenStore_SaveRejectsNil(t *testing.T) {
	s := NewMemoryTokenStore()
	if err := s.Save("alice", "slack", nil); err == nil {
		t.Fatal("Save(nil) should error")
	}
}

func TestMemoryTokenStore_GetReturnsCopy(t *testing.T) {
	// Mutating the returned struct must not affect the stored one — the
	// gateway relies on this to avoid races between concurrent tool calls.
	s := NewMemoryTokenStore()
	if err := s.Save("alice", "slack", &Tokens{
		AccessToken: "at",
		Scopes:      []string{"a", "b"},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out1, _ := s.Get("alice", "slack")
	out1.AccessToken = "mutated"
	out1.Scopes[0] = "X"

	out2, _ := s.Get("alice", "slack")
	if out2.AccessToken != "at" {
		t.Errorf("AccessToken was mutated through returned pointer: %q", out2.AccessToken)
	}
	if out2.Scopes[0] != "a" {
		t.Errorf("Scopes slice was mutated through returned pointer: %v", out2.Scopes)
	}
}

func TestMemoryTokenStore_Delete(t *testing.T) {
	s := NewMemoryTokenStore()
	if err := s.Save("alice", "slack", &Tokens{AccessToken: "at"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Delete("alice", "slack"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("alice", "slack"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete Get returned %v, want ErrNotFound", err)
	}
	// Idempotent.
	if err := s.Delete("alice", "slack"); err != nil {
		t.Errorf("second Delete should be no-op, got %v", err)
	}
}

func TestTokens_ExpiredAndNeedsRefresh(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name             string
		expiresAt        time.Time
		wantExpired      bool
		wantNeedsRefresh bool
	}{
		{"zero never expires", time.Time{}, false, false},
		{"past", now.Add(-time.Hour), true, true},
		{"within leeway", now.Add(30 * time.Second), false, true},
		{"comfortably ahead", now.Add(10 * time.Minute), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok := &Tokens{ExpiresAt: c.expiresAt}
			if got := tok.Expired(); got != c.wantExpired {
				t.Errorf("Expired() = %v, want %v", got, c.wantExpired)
			}
			if got := tok.NeedsRefresh(); got != c.wantNeedsRefresh {
				t.Errorf("NeedsRefresh() = %v, want %v", got, c.wantNeedsRefresh)
			}
		})
	}
}

// fakeRefresher records every refresh call and returns a deterministic new
// access token so tests can assert on the swap.
type fakeRefresher struct {
	mu    sync.Mutex
	calls int
	next  Tokens
	err   error
}

func (f *fakeRefresher) Refresh(_ context.Context, _, _ string) (*Tokens, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	cp := f.next
	return &cp, nil
}

func TestRefreshingTokenStore_RefreshesWithinLeeway(t *testing.T) {
	inner := NewMemoryTokenStore()
	if err := inner.Save("alice", "slack", &Tokens{
		AccessToken:  "old",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(10 * time.Second), // within leeway
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fr := &fakeRefresher{next: Tokens{
		AccessToken:  "new",
		RefreshToken: "rt2",
		ExpiresAt:    time.Now().Add(time.Hour),
	}}
	rs := NewRefreshingTokenStore(inner, fr)

	out, err := rs.Get(context.Background(), "alice", "slack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.AccessToken != "new" {
		t.Errorf("AccessToken = %q, want %q", out.AccessToken, "new")
	}
	if fr.calls != 1 {
		t.Errorf("refresh calls = %d, want 1", fr.calls)
	}
	// Persisted back to inner.
	persisted, _ := inner.Get("alice", "slack")
	if persisted.AccessToken != "new" || persisted.RefreshToken != "rt2" {
		t.Errorf("inner not updated: %+v", persisted)
	}
}

func TestRefreshingTokenStore_DoesNotRefreshOutsideLeeway(t *testing.T) {
	inner := NewMemoryTokenStore()
	if err := inner.Save("alice", "slack", &Tokens{
		AccessToken:  "still-good",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fr := &fakeRefresher{}
	rs := NewRefreshingTokenStore(inner, fr)

	out, err := rs.Get(context.Background(), "alice", "slack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.AccessToken != "still-good" {
		t.Errorf("AccessToken = %q, want still-good", out.AccessToken)
	}
	if fr.calls != 0 {
		t.Errorf("refresh fired when token was fresh: %d calls", fr.calls)
	}
}

func TestRefreshingTokenStore_CarryForwardRefreshToken(t *testing.T) {
	// Some providers omit refresh_token on refresh responses. The decorator
	// must carry the previous one forward so the user does not become
	// silently unrefreshable.
	inner := NewMemoryTokenStore()
	if err := inner.Save("alice", "slack", &Tokens{
		AccessToken:  "old",
		RefreshToken: "rt_keep",
		ExpiresAt:    time.Now().Add(10 * time.Second),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fr := &fakeRefresher{next: Tokens{
		AccessToken: "new",
		// RefreshToken intentionally empty
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	rs := NewRefreshingTokenStore(inner, fr)

	out, err := rs.Get(context.Background(), "alice", "slack")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.RefreshToken != "rt_keep" {
		t.Errorf("RefreshToken = %q, want it carried forward", out.RefreshToken)
	}
}

func TestRefreshingTokenStore_RefresherErrorSurfaces(t *testing.T) {
	inner := NewMemoryTokenStore()
	if err := inner.Save("alice", "slack", &Tokens{
		AccessToken:  "old",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(10 * time.Second),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fr := &fakeRefresher{err: errors.New("upstream refused")}
	rs := NewRefreshingTokenStore(inner, fr)

	_, err := rs.Get(context.Background(), "alice", "slack")
	if err == nil {
		t.Fatal("expected error from failed refresh")
	}
}

func TestRefreshingTokenStore_GetMissingIsNotFound(t *testing.T) {
	rs := NewRefreshingTokenStore(NewMemoryTokenStore(), &fakeRefresher{})
	_, err := rs.Get(context.Background(), "alice", "slack")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
