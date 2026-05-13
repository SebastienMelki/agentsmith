package oauth

import (
	"testing"
)

func TestSessionStore_CreateAndMarkGranted(t *testing.T) {
	s := NewSessionStore()
	id, err := s.create(&authzSession{
		ClientID: "c",
		UserID:   "u",
		Pending:  []string{"slack:*", "dodo:*"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == "" {
		t.Fatal("empty session ID")
	}
	sess := s.markGranted(id, "slack:*")
	if sess == nil {
		t.Fatal("markGranted returned nil for fresh session")
	}
	if len(sess.Pending) != 1 || sess.Pending[0] != "dodo:*" {
		t.Errorf("pending after grant = %v, want [dodo:*]", sess.Pending)
	}
	if len(sess.Granted) != 1 || sess.Granted[0] != "slack:*" {
		t.Errorf("granted = %v, want [slack:*]", sess.Granted)
	}
}

func TestSessionStore_MarkUnknownReturnsNil(t *testing.T) {
	s := NewSessionStore()
	if got := s.markGranted("nope", "slack:*"); got != nil {
		t.Errorf("markGranted on unknown = %+v, want nil", got)
	}
}

func TestSessionStore_RemoveDeletes(t *testing.T) {
	s := NewSessionStore()
	id, _ := s.create(&authzSession{ClientID: "c", UserID: "u"})
	s.remove(id)
	if got := s.markGranted(id, "slack:*"); got != nil {
		t.Errorf("session should be gone after remove, got %+v", got)
	}
}
