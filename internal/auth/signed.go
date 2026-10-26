package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"platypus/internal/config"
)

// supportedAlgorithms are the signing algorithms accepted from login proxies.
// Symmetric algorithms (HS256) are not: anyone with the shared secret could
// forge tokens.
var supportedAlgorithms = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
	oidc.EdDSA,
}

// SignedHeader is signed-header mode: the login proxy sends a signed token
// (JWT), and platypus verifies its signature, issuer, audience and expiry.
// A request that bypassed the proxy, or a forged header, fails here.
type SignedHeader struct {
	header      string
	verifier    *oidc.IDTokenVerifier
	emailClaim  string
	groupsClaim string
}

// NewSignedHeader returns a SignedHeader. ctx must live as long as platypus:
// the public keys are fetched, and refreshed, with it.
func NewSignedHeader(ctx context.Context, cfg config.SignedHeader) *SignedHeader {
	ctx = oidc.ClientContext(ctx, httpClient)
	keys := oidc.NewRemoteKeySet(ctx, cfg.JWKSURL)
	return &SignedHeader{
		header: cfg.Name,
		verifier: oidc.NewVerifier(cfg.Issuer, keys, &oidc.Config{
			ClientID:             cfg.Audience,
			SupportedSigningAlgs: supportedAlgorithms,
		}),
		emailClaim:  cfg.EmailClaim,
		groupsClaim: cfg.GroupsClaim,
	}
}

// Verify checks the token in the header and returns who it belongs to.
func (s *SignedHeader) Verify(r *http.Request) (Identity, error) {
	raw := strings.TrimSpace(r.Header.Get(s.header))
	if strings.EqualFold(s.header, "Authorization") {
		raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	}
	if raw == "" {
		return Identity{}, ErrNotAuthenticated
	}
	token, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
	}
	return identityFromClaims(token, s.emailClaim, s.groupsClaim)
}

// identityFromClaims reads the email address, name and groups from a verified
// token. A token that says the email address isn't verified is refused.
func identityFromClaims(token *oidc.IDToken, emailClaim, groupsClaim string) (Identity, error) {
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("%w: unreadable claims", ErrNotAuthenticated)
	}
	email, _ := claims[emailClaim].(string)
	if email == "" {
		return Identity{}, fmt.Errorf("%w: the token has no %q claim", ErrNotAuthenticated, emailClaim)
	}
	if verified, present := claims["email_verified"]; present && verified != true && verified != "true" {
		return Identity{}, fmt.Errorf("%w: the email address is not verified", ErrNotAuthenticated)
	}
	name, _ := claims["name"].(string)
	var groups []string
	if groupsClaim != "" {
		cleaned, err := groupsFromClaim(claims, groupsClaim)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
		}
		groups = cleaned
	}
	return Identity{Email: email, Name: name, Groups: groups}, nil
}
