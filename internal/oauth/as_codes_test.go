package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestCodeStore_SingleUse(t *testing.T) {
	s := NewCodeStore()
	c := &authorizationCode{Code: "abc", Expires: time.Now().Add(time.Minute)}
	s.put(c)
	if s.take("abc") == nil {
		t.Fatal("first take should succeed")
	}
	if s.take("abc") != nil {
		t.Fatal("second take should be nil — codes are single-use")
	}
}

func TestCodeStore_ExpiredDropped(t *testing.T) {
	s := NewCodeStore()
	s.put(&authorizationCode{Code: "abc", Expires: time.Now().Add(-time.Second)})
	if s.take("abc") != nil {
		t.Fatal("expired code should not be returned")
	}
}

func TestTokenStore_IssueAndLookup(t *testing.T) {
	s := NewASTokenStore()
	tok, err := s.Issue("client", "alice", []string{"slack:*"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Errorf("tokens not populated: %+v", tok)
	}
	got, err := s.Lookup(tok.AccessToken)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.UserID != "alice" || got.ClientID != "client" {
		t.Errorf("token identity mismatch: %+v", got)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "slack:*" {
		t.Errorf("scopes = %v", got.Scopes)
	}
}

func TestTokenStore_LookupUnknown(t *testing.T) {
	s := NewASTokenStore()
	if _, err := s.Lookup("nope"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

func TestTokenStore_RotateRevokesOld(t *testing.T) {
	s := NewASTokenStore()
	old, _ := s.Issue("c", "u", []string{"a:*"})
	newer, err := s.Rotate(old.RefreshToken)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newer.AccessToken == old.AccessToken || newer.RefreshToken == old.RefreshToken {
		t.Error("rotation did not produce fresh tokens")
	}
	if _, err := s.Lookup(old.AccessToken); !errors.Is(err, ErrTokenNotFound) {
		t.Error("old access token should be revoked after rotate")
	}
	if _, err := s.Rotate(old.RefreshToken); !errors.Is(err, ErrTokenNotFound) {
		t.Error("old refresh token should be revoked after rotate")
	}
}

func TestVerifyPKCE_S256Match(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Errorf("VerifyPKCE: %v", err)
	}
}

func TestVerifyPKCE_RejectsMismatch(t *testing.T) {
	if err := VerifyPKCE("verifier", "wrong-challenge", "S256"); err == nil {
		t.Error("expected error on mismatch")
	}
}

func TestVerifyPKCE_RejectsNonS256(t *testing.T) {
	if err := VerifyPKCE("v", "c", "plain"); err == nil {
		t.Error("expected error for plain method")
	}
}
