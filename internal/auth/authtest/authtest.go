// Package authtest is a minimal OpenID Connect provider for tests:
// discovery, signing keys, an authorize endpoint that logs in whoever the
// test chooses, and a token endpoint with PKCE. It also signs arbitrary
// tokens for testing signed-header mode.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	ClientID     = "platypus-test"
	ClientSecret = "platypus-test-secret"
	keyID        = "test-key"
)

// Provider is a running test identity provider.
type Provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer

	mu    sync.Mutex
	user  User
	codes map[string]grant
}

// User is who logs in at the authorize endpoint.
type User struct {
	Email         string
	Name          string
	EmailVerified bool
	// Groups appear in the ID token's groups claim.
	Groups []string
}

type grant struct {
	nonce     string
	challenge string
	user      User
}

// New starts a provider that is stopped when the test ends.
func New(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{key: key, signer: signer, codes: map[string]grant{},
		user: User{Email: "user@example.com", Name: "Test User", EmailVerified: true}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", p.keys)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func newSigner(key *rsa.PrivateKey) (jose.Signer, error) {
	return jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID))
}

// Issuer is the provider's issuer URL.
func (p *Provider) Issuer() string { return p.server.URL }

// JWKSURL is where the provider publishes its public keys.
func (p *Provider) JWKSURL() string { return p.server.URL + "/keys" }

// LogInAs sets who logs in at the authorize endpoint from now on.
func (p *Provider) LogInAs(user User) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = user
}

// Sign returns a token with the given claims, signed with the provider's key.
func (p *Provider) Sign(t testing.TB, claims map[string]any) string {
	t.Helper()
	token, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// SignWithOtherKey returns a token signed with a key the provider doesn't
// publish, as a forger would.
func (p *Provider) SignWithOtherKey(t testing.TB, claims map[string]any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Claims returns standard claims for a token from this provider.
func (p *Provider) Claims(audience, email string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            p.Issuer(),
		"aud":            audience,
		"sub":            "subject-" + email,
		"email":          email,
		"email_verified": true,
		"name":           "Test User",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.server.URL + "/authorize",
		"token_endpoint":                        p.server.URL + "/token",
		"jwks_uri":                              p.JWKSURL(),
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (p *Provider) keys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &p.key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"},
	}})
}

// authorize logs in the configured user straight away and sends the browser
// back with a code, like a provider where the user is already logged in.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != ClientID || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	p.codes[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), user: p.user}
	p.mu.Unlock()

	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	values := back.Query()
	values.Set("code", code)
	values.Set("state", q.Get("state"))
	back.RawQuery = values.Encode()
	// A test provider: it redirects wherever the test's client asks.
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // see above
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != ClientID || secret != ClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostFormValue("code")]
	delete(p.codes, r.PostFormValue("code"))
	p.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	claims := p.Claims(ClientID, g.user.Email)
	claims["nonce"] = g.nonce
	claims["name"] = g.user.Name
	claims["email_verified"] = g.user.EmailVerified
	if len(g.user.Groups) > 0 {
		groups := make([]any, len(g.user.Groups))
		for i, group := range g.user.Groups {
			groups[i] = group
		}
		claims["groups"] = groups
	}
	idToken, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": randomString(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
