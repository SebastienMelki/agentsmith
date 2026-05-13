package oauth

import (
	"strings"
	"testing"
	"time"
)

func TestTicket_SignVerifyRoundTrip(t *testing.T) {
	s, err := NewTicketSigner("supersecretkey0123456789abcdefgh")
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
	s, _ := NewTicketSigner("supersecretkey0123456789abcdefgh")
	tok, _ := s.Sign("alice", "slack", time.Minute)

	// Flip one character of the body half.
	parts := strings.SplitN(tok, ".", 2)
	tampered := parts[0][:len(parts[0])-1] + "X" + "." + parts[1]
	if _, _, err := s.Verify(tampered); err == nil {
		t.Fatal("Verify should have rejected tampered body")
	}
}

func TestTicket_ExpiredFails(t *testing.T) {
	s, _ := NewTicketSigner("supersecretkey0123456789abcdefgh")
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
	a, _ := NewTicketSigner("supersecretkeyAAAAAAAAAAaaaaaaaaaa")
	b, _ := NewTicketSigner("supersecretkeyBBBBBBBBBBbbbbbbbbbb")
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

// TestNewTicketSigner_RejectsKeysBelowMinimum pins the floor: a 31-char key
// is below the operator-input minimum and must be rejected even though older
// code accepted anything ≥ 16. Lifting this floor raises the entropy of
// operator-supplied secrets from ~96 bits (16 printable ASCII chars) toward
// ~192 bits (32 chars).
func TestNewTicketSigner_RejectsKeysBelowMinimum(t *testing.T) {
	justBelow := strings.Repeat("a", minTicketKeyLen-1)
	if _, err := NewTicketSigner(justBelow); err == nil {
		t.Fatalf("key of length %d should be rejected", len(justBelow))
	}
	exactlyMin := strings.Repeat("a", minTicketKeyLen)
	if _, err := NewTicketSigner(exactlyMin); err != nil {
		t.Fatalf("key of length %d should be accepted: %v", len(exactlyMin), err)
	}
}

func TestTicket_MalformedRejects(t *testing.T) {
	s, _ := NewTicketSigner("supersecretkey0123456789abcdefgh")
	if _, _, err := s.Verify("no-dot-here"); err == nil {
		t.Fatal("missing dot should be rejected")
	}
}
