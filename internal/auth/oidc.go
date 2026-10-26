package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"platypus/internal/config"
	"platypus/internal/problem"
	"platypus/internal/seal"
)

const (
	// CallbackPath is where the identity provider sends the browser back.
	CallbackPath = "/auth/callback"

	loginCookie       = "platypus_login"
	loginCookieMaxAge = 10 * time.Minute
)

// sealContext binds sealed login state to its purpose.
var sealContext = []byte("platypus login state")

// OIDC is oidc mode: platypus logs people in itself with the authorization
// code flow and PKCE. Between the redirect to the identity provider and the
// callback, the login state (state, nonce, PKCE verifier, where to return)
// lives in a short-lived, encrypted cookie, so nothing is stored for people
// who haven't logged in yet.
type OIDC struct {
	oauth      oauth2.Config
	prompt     string
	verifier   *oidc.IDTokenVerifier
	emailClaim string
	// groupsClaim names the ID token claim with the user's groups; empty
	// switches group mapping off.
	groupsClaim string
	sealer      *seal.Sealer
	secure      bool
	now         func() time.Time
}

// NewOIDC discovers the identity provider's endpoints. secure sets the
// Secure flag on the login cookie (plain http only in test mode).
func NewOIDC(ctx context.Context, cfg config.OIDC, publicURL *url.URL, sealer *seal.Sealer, secure bool) (*OIDC, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover the OIDC provider %s: %w", cfg.Issuer, err)
	}
	return &OIDC{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret.Reveal(),
			Endpoint:     provider.Endpoint(),
			RedirectURL:  strings.TrimSuffix(publicURL.String(), "/") + CallbackPath,
			Scopes:       cfg.Scopes,
		},
		prompt:      cfg.Prompt,
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: supportedAlgorithms}),
		emailClaim:  cfg.EmailClaim,
		groupsClaim: cfg.GroupsClaim,
		sealer:      sealer,
		secure:      secure,
		now:         time.Now,
	}, nil
}

// loginState is what the login cookie carries from StartLogin to FinishLogin.
type loginState struct {
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	ReturnTo string    `json:"return_to"`
	Expires  time.Time `json:"expires"`
}

// StartLogin returns the identity provider's login URL and sets the login
// cookie. returnTo is where to go after the login.
func (o *OIDC) StartLogin(w http.ResponseWriter, returnTo string) (string, error) {
	state := loginState{
		State:    randomString(),
		Nonce:    randomString(),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: SafeReturnPath(returnTo),
		Expires:  o.now().Add(loginCookieMaxAge),
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sealed, err := o.sealer.Seal(plain, sealContext)
	if err != nil {
		return "", err
	}
	// Secure is only false in test mode on plain http (see NewOIDC).
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name:     loginCookie,
		Value:    base64.RawURLEncoding.EncodeToString(sealed),
		Path:     CallbackPath,
		MaxAge:   int(loginCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   o.secure,
		// Lax, not Strict: the callback is a navigation coming from the
		// identity provider's site, and must carry this cookie.
		SameSite: http.SameSiteLaxMode,
	})
	options := []oauth2.AuthCodeOption{oidc.Nonce(state.Nonce), oauth2.S256ChallengeOption(state.Verifier)}
	if o.prompt != "" {
		options = append(options, oauth2.SetAuthURLParam("prompt", o.prompt))
	}
	return o.oauth.AuthCodeURL(state.State, options...), nil
}

// errLoginRetry is shown when the login can't be completed and simply
// starting over will do.
var errLoginRetry = problem.Forbidden("The login could not be completed: it took too long or was started in another tab. Please log in again.")

// FinishLogin completes the login on the callback request: it checks the
// state, exchanges the code, verifies the ID token and returns who logged in
// and where they wanted to go. The login cookie is removed either way.
func (o *OIDC) FinishLogin(w http.ResponseWriter, r *http.Request) (Identity, string, error) {
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Path: CallbackPath, MaxAge: -1, //nolint:gosec // removes the cookie
		HttpOnly: true, Secure: o.secure, SameSite: http.SameSiteLaxMode})

	state, err := o.readState(r)
	if err != nil {
		return Identity{}, "", errors.Join(errLoginRetry, err)
	}
	query := r.URL.Query()
	if reason := query.Get("error"); reason != "" {
		return Identity{}, "", problem.Forbidden("The identity provider did not log you in (%s).", reason)
	}
	if query.Get("state") != state.State {
		return Identity{}, "", errors.Join(errLoginRetry, errors.New("state mismatch"))
	}

	ctx := oidc.ClientContext(r.Context(), httpClient)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	token, err := o.oauth.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(state.Verifier))
	if err != nil {
		return Identity{}, "", fmt.Errorf("exchange the login code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return Identity{}, "", errors.New("the identity provider returned no ID token")
	}
	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, "", fmt.Errorf("verify the ID token: %w", err)
	}
	if idToken.Nonce != state.Nonce {
		return Identity{}, "", errors.Join(errLoginRetry, errors.New("nonce mismatch"))
	}
	identity, err := identityFromClaims(idToken, o.emailClaim, o.groupsClaim)
	if err != nil {
		return Identity{}, "", problem.Forbidden("The identity provider did not confirm your email address.")
	}
	return identity, state.ReturnTo, nil
}

func (o *OIDC) readState(r *http.Request) (loginState, error) {
	cookie, err := r.Cookie(loginCookie)
	if err != nil {
		return loginState{}, errors.New("no login cookie")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return loginState{}, errors.New("malformed login cookie")
	}
	plain, err := o.sealer.Open(sealed, sealContext, o.sealer.KeyID())
	if err != nil {
		return loginState{}, err
	}
	var state loginState
	if err := json.Unmarshal(plain, &state); err != nil {
		return loginState{}, err
	}
	if !o.now().Before(state.Expires) {
		return loginState{}, errors.New("login state expired")
	}
	return state, nil
}

// SafeReturnPath keeps only local paths, so a crafted login link can't send
// people to another site afterwards.
func SafeReturnPath(path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.HasPrefix(path, "/\\") ||
		strings.HasPrefix(path, CallbackPath) {
		return "/"
	}
	return path
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
