package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TicketSigner mints short-lived signed tickets that identify the user when
// they hit /oauth/connect from a browser. The browser does not carry the
// user's API key, so the tool-error message that surfaced the connect URL
// embeds a ticket instead. The ticket is HMAC-SHA256-signed with a key that
// only the gateway knows.
type TicketSigner struct {
	key []byte
}

// NewTicketSigner returns a signer that uses the given secret key. Empty key
// is rejected so an operator does not accidentally disable signing.
func NewTicketSigner(key string) (*TicketSigner, error) {
	if len(key) < 16 {
		return nil, errors.New("oauth: ticket signing key must be at least 16 characters")
	}
	return &TicketSigner{key: []byte(key)}, nil
}

// ticketPayload is the JSON body of a signed ticket.
type ticketPayload struct {
	UserID  string `json:"uid"`
	Backend string `json:"backend"`
	Expires int64  `json:"exp"` // unix seconds
}

// Sign returns a URL-safe token of the form base64url(payload).base64url(mac).
// The token carries enough information to authenticate the user and to scope
// the OAuth flow to a single backend.
func (s *TicketSigner) Sign(userID, backend string, ttl time.Duration) (string, error) {
	payload, err := json.Marshal(ticketPayload{
		UserID:  userID,
		Backend: backend,
		Expires: time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig, nil
}

// Verify parses a signed ticket and checks the HMAC + expiry. Returns the
// (userID, backend) pair or an error explaining why verification failed.
func (s *TicketSigner) Verify(token string) (userID, backend string, err error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return "", "", errors.New("oauth: ticket malformed")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", "", fmt.Errorf("oauth: ticket signature decode: %w", err)
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(body))
	want := mac.Sum(nil)
	if !hmac.Equal(got, want) {
		return "", "", errors.New("oauth: ticket signature invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", "", fmt.Errorf("oauth: ticket payload decode: %w", err)
	}
	var p ticketPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", "", fmt.Errorf("oauth: ticket payload parse: %w", err)
	}
	if time.Now().Unix() > p.Expires {
		return "", "", errors.New("oauth: ticket expired")
	}
	return p.UserID, p.Backend, nil
}
