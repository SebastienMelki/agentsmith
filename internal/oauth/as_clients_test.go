package oauth

import (
	"errors"
	"strings"
	"testing"
)

func TestClientStore_RegisterAndLookup(t *testing.T) {
	cs := NewClientStore()
	c, err := cs.Register("ClaudeCode", []string{"http://localhost:1234/cb"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c.ID == "" || !strings.HasPrefix(c.ID, "as_") {
		t.Errorf("client id = %q, want non-empty with as_ prefix", c.ID)
	}
	got, err := cs.Lookup(c.ID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "ClaudeCode" {
		t.Errorf("name = %q", got.Name)
	}
	if !got.AllowsRedirect("http://localhost:1234/cb") {
		t.Error("AllowsRedirect rejected the registered URI")
	}
	if got.AllowsRedirect("http://evil.example/cb") {
		t.Error("AllowsRedirect accepted an unregistered URI")
	}
}

func TestClientStore_LookupUnknown(t *testing.T) {
	cs := NewClientStore()
	if _, err := cs.Lookup("nope"); !errors.Is(err, ErrUnknownClient) {
		t.Errorf("err = %v, want ErrUnknownClient", err)
	}
}

func TestClientStore_RegisterRequiresRedirectURI(t *testing.T) {
	cs := NewClientStore()
	if _, err := cs.Register("x", nil); err == nil {
		t.Error("expected error for empty redirect_uris")
	}
}
