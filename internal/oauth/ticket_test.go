package oauth

import (
	"strings"
	"testing"
	"time"
)

func TestTicket_SignVerifyRoundTrip(t *testing.T) {
	s, err := NewTicketSigner("supersecretkey0123456789")
	if err != nil {
		t.Fatalf("NewTicketSigner: %v", err)
	}
	tok, err := s.Sign("alice@acme.com", "slack", time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	uid, backend, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if uid != "alice@acme.com" {
		t.Errorf("uid = %q", uid)
	}
	if backend != "slack" {
		t.Errorf("backend = %q", backend)
	}
}

func TestTicket_TamperedFails(t *testing.T) {
	s, _ := NewTicketSigner("supersecretkey0123456789")
	tok, _ := s.Sign("alice", "slack", time.Minute)

	// Flip one character of the body half.
	parts := strings.SplitN(tok, ".", 2)
	tampered := parts[0][:len(parts[0])-1] + "X" + "." + parts[1]
	if _, _, err := s.Verify(tampered); err == nil {
		t.Fatal("Verify should have rejected tampered body")
	}
}

func TestTicket_ExpiredFails(t *testing.T) {
	s, _ := NewTicketSigner("supersecretkey0123456789")
	tok, err := s.Sign("alice", "slack", -1*time.Second)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, _, err = s.Verify(tok)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("Verify(expired) = %v, want expired error", err)
	}
}

func TestTicket_DifferentKeyRejects(t *testing.T) {
	a, _ := NewTicketSigner("supersecretkeyAAAAAAAAAA")
	b, _ := NewTicketSigner("supersecretkeyBBBBBBBBBB")
	tok, _ := a.Sign("alice", "slack", time.Minute)
	if _, _, err := b.Verify(tok); err == nil {
		t.Fatal("Verify with different key should fail")
	}
}

func TestNewTicketSigner_ShortKeyRejected(t *testing.T) {
	if _, err := NewTicketSigner("short"); err == nil {
		t.Fatal("short key should be rejected")
	}
}

func TestTicket_MalformedRejects(t *testing.T) {
	s, _ := NewTicketSigner("supersecretkey0123456789")
	if _, _, err := s.Verify("no-dot-here"); err == nil {
		t.Fatal("missing dot should be rejected")
	}
}
