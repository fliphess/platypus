// Package auth tells platypus who sends a request. There are three ways,
// exactly one of which is configured (PLATYPUS_AUTH_MODE):
//
//   - header: a login proxy in front of platypus sets a header with the
//     user's email. Platypus trusts it; the gateway must strip it from
//     incoming requests.
//   - signed-header: a login proxy sends a signed token (JWT), which
//     platypus verifies against the proxy's public keys.
//   - oidc: platypus logs people in itself with OpenID Connect; the login
//     then lives in platypus's own session.
//
// The first two identify every request on their own (RequestVerifier). OIDC
// runs a login flow once (see OIDC) and the web layer keeps the session.
package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Identity is a person as the login method reports them. Email is not yet
// normalised or checked against the allowed domains; the caller does that.
// Groups holds the identity provider's groups for the user, cleaned and
// sorted; nil when the mode doesn't read groups.
type Identity struct {
	Email  string
	Name   string
	Groups []string
}

// ErrNotAuthenticated means the request carries no valid identity.
var ErrNotAuthenticated = errors.New("not authenticated")

// RequestVerifier identifies each request on its own: header and
// signed-header mode.
type RequestVerifier interface {
	Verify(r *http.Request) (Identity, error)
}

// httpClient talks to identity providers: their keys, discovery documents and
// token endpoints. A timeout keeps a slow provider from hanging requests.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// Header is header mode: the email address comes from a header the login
// proxy sets.
type Header struct {
	name       string
	groupsName string
}

// NewHeader returns a Header reading the given headers. groupsName, when not
// empty, is a header holding the user's groups as a comma-separated list,
// trusted exactly like the identity header.
func NewHeader(name, groupsName string) *Header {
	return &Header{name: name, groupsName: groupsName}
}

// Verify returns the email address in the header.
func (h *Header) Verify(r *http.Request) (Identity, error) {
	email := strings.TrimSpace(r.Header.Get(h.name))
	if email == "" {
		return Identity{}, ErrNotAuthenticated
	}
	identity := Identity{Email: email}
	if h.groupsName != "" {
		groups, err := groupsFromHeader(r.Header.Get(h.groupsName))
		if err != nil {
			return Identity{}, fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
		}
		identity.Groups = groups
	}
	return identity, nil
}
