package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"platypus/internal/auth"
	"platypus/internal/auth/authtest"
	"platypus/internal/config"
	"platypus/internal/problem"
	"platypus/internal/seal"
	"platypus/internal/sensitive"
)

func request(header, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		r.Header.Set(header, value)
	}
	return r
}

func TestHeader(t *testing.T) {
	h := auth.NewHeader("X-Auth-Request-Email", "")
	if _, err := h.Verify(request("", "")); !errors.Is(err, auth.ErrNotAuthenticated) {
		t.Errorf("no header: %v", err)
	}
	identity, err := h.Verify(request("X-Auth-Request-Email", " jane@example.com "))
	if err != nil || identity.Email != "jane@example.com" {
		t.Errorf("Verify = %+v, %v", identity, err)
	}
	if identity.Groups != nil {
		t.Errorf("groups read without a groups header configured: %+v", identity.Groups)
	}
}

func TestHeaderGroups(t *testing.T) {
	h := auth.NewHeader("X-Auth-Request-Email", "X-Auth-Request-Groups")
	r := request("X-Auth-Request-Email", "jane@example.com")

	identity, err := h.Verify(r)
	if err != nil || identity.Groups == nil || len(identity.Groups) != 0 {
		// No header at all is still "no groups", not "mapping off": an empty
		// list, so the sync runs and removes linked-team memberships.
		t.Errorf("no groups header: %+v, %v", identity, err)
	}

	r.Header.Set("X-Auth-Request-Groups", " platform ,Payments,platform, ")
	identity, err = h.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Payments", "platform"}
	if !slices.Equal(identity.Groups, want) {
		t.Errorf("Groups = %q, want %q", identity.Groups, want)
	}

	r.Header.Set("X-Auth-Request-Groups", "  ")
	if identity, err = h.Verify(r); err != nil || len(identity.Groups) != 0 {
		t.Errorf("blank groups header: %+v, %v", identity, err)
	}
}

func TestSignedHeaderGroups(t *testing.T) {
	idp := authtest.New(t)
	const audience = "platypus-audience"
	verifier := auth.NewSignedHeader(context.Background(), config.SignedHeader{
		Name: "X-Signed-Assertion", JWKSURL: idp.JWKSURL(), Issuer: idp.Issuer(),
		Audience: audience, EmailClaim: "email", GroupsClaim: "groups",
	})

	with := func(change func(map[string]any)) *http.Request {
		claims := idp.Claims(audience, "jane@example.com")
		change(claims)
		return request("X-Signed-Assertion", idp.Sign(t, claims))
	}

	identity, err := verifier.Verify(with(func(c map[string]any) { c["groups"] = []any{"platform", "Payments"} }))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Payments", "platform"}; !slices.Equal(identity.Groups, want) {
		t.Errorf("Groups = %q, want %q", identity.Groups, want)
	}

	identity, err = verifier.Verify(with(func(c map[string]any) { c["groups"] = "one-group" }))
	if err != nil || !slices.Equal(identity.Groups, []string{"one-group"}) {
		t.Errorf("single group: %+v, %v", identity, err)
	}

	bad := map[string]func(map[string]any){
		"non-string entry": func(c map[string]any) { c["groups"] = []any{"platform", 7} },
		"claim of numbers": func(c map[string]any) { c["groups"] = []any{1, 2} },
		"claim an object":  func(c map[string]any) { c["groups"] = map[string]any{"a": "b"} },
		"name too long":    func(c map[string]any) { c["groups"] = []any{strings.Repeat("g", 201)} },
		"too many groups":  func(c map[string]any) { c["groups"] = manyGroups(51) },
	}
	for name, change := range bad {
		if _, err := verifier.Verify(with(change)); !errors.Is(err, auth.ErrNotAuthenticated) {
			t.Errorf("%s: accepted (err = %v)", name, err)
		}
	}
}

func manyGroups(n int) []any {
	groups := make([]any, n)
	for i := range groups {
		groups[i] = "group-" + fmt.Sprint(i)
	}
	return groups
}

func TestSignedHeader(t *testing.T) {
	idp := authtest.New(t)
	const audience = "platypus-audience"
	verifier := auth.NewSignedHeader(context.Background(), config.SignedHeader{
		Name: "X-Signed-Assertion", JWKSURL: idp.JWKSURL(), Issuer: idp.Issuer(),
		Audience: audience, EmailClaim: "email",
	})

	identity, err := verifier.Verify(request("X-Signed-Assertion", idp.Sign(t, idp.Claims(audience, "jane@example.com"))))
	if err != nil || identity.Email != "jane@example.com" || identity.Name != "Test User" {
		t.Fatalf("valid token: %+v, %v", identity, err)
	}

	with := func(change func(map[string]any)) string {
		claims := idp.Claims(audience, "jane@example.com")
		change(claims)
		return idp.Sign(t, claims)
	}
	bad := map[string]string{
		"no header":         "",
		"garbage":           "not-a-jwt",
		"wrong audience":    with(func(c map[string]any) { c["aud"] = "someone-else" }),
		"wrong issuer":      with(func(c map[string]any) { c["iss"] = "https://evil.example.com" }),
		"expired":           with(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"unverified email":  with(func(c map[string]any) { c["email_verified"] = false }),
		"no email":          with(func(c map[string]any) { delete(c, "email") }),
		"forged signature":  idp.SignWithOtherKey(t, idp.Claims(audience, "jane@example.com")),
		"symmetric (HS256)": hs256(t, idp.Claims(audience, "jane@example.com")),
	}
	for name, token := range bad {
		if _, err := verifier.Verify(request("X-Signed-Assertion", token)); !errors.Is(err, auth.ErrNotAuthenticated) {
			t.Errorf("%s: accepted (err = %v)", name, err)
		}
	}

	bearer := auth.NewSignedHeader(context.Background(), config.SignedHeader{
		Name: "Authorization", JWKSURL: idp.JWKSURL(), Issuer: idp.Issuer(), Audience: audience, EmailClaim: "email",
	})
	token := idp.Sign(t, idp.Claims(audience, "jane@example.com"))
	if _, err := bearer.Verify(request("Authorization", "Bearer "+token)); err != nil {
		t.Errorf("Authorization: Bearer token: %v", err)
	}
}

// hs256 signs with a shared secret, which must never be accepted.
func hs256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("shared-secret-shared-secret-32by")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func newOIDC(t *testing.T, idp *authtest.Provider) *auth.OIDC {
	return newOIDCConfigured(t, idp, "")
}

func newOIDCWithGroups(t *testing.T, idp *authtest.Provider) *auth.OIDC {
	return newOIDCConfigured(t, idp, "groups")
}

func newOIDCConfigured(t *testing.T, idp *authtest.Provider, groupsClaim string) *auth.OIDC {
	t.Helper()
	sealer, err := seal.New(sensitive.New(config.TestEncryptionKey))
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://platypus.example.com")
	o, err := auth.NewOIDC(context.Background(), config.OIDC{
		Issuer: idp.Issuer(), ClientID: authtest.ClientID, ClientSecret: sensitive.New(authtest.ClientSecret),
		Scopes: []string{"openid", "email", "profile"}, EmailClaim: "email", GroupsClaim: groupsClaim,
	}, publicURL, sealer, true)
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	return o
}

// login runs the flow up to the callback: start, visit the provider, return
// the callback request with the login cookie, as a browser would.
func login(t *testing.T, o *auth.OIDC, returnTo string) *http.Request {
	t.Helper()
	start := httptest.NewRecorder()
	providerURL, err := o.StartLogin(start, returnTo)
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if !strings.Contains(providerURL, "code_challenge=") || !strings.Contains(providerURL, "nonce=") {
		t.Fatalf("login URL lacks PKCE or nonce: %s", providerURL)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(providerURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	callback := httptest.NewRequest(http.MethodGet, resp.Header.Get("Location"), nil)
	for _, c := range start.Result().Cookies() {
		callback.AddCookie(c)
	}
	return callback
}

func TestOIDCLogin(t *testing.T) {
	idp := authtest.New(t)
	o := newOIDC(t, idp)
	idp.LogInAs(authtest.User{Email: "jane@example.com", Name: "Jane Doe", EmailVerified: true})

	identity, returnTo, err := o.FinishLogin(httptest.NewRecorder(), login(t, o, "/secrets?q=db"))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if identity.Email != "jane@example.com" || identity.Name != "Jane Doe" || returnTo != "/secrets?q=db" {
		t.Errorf("FinishLogin = %+v, %q", identity, returnTo)
	}
}

func TestOIDCLoginGroups(t *testing.T) {
	idp := authtest.New(t)
	o := newOIDCWithGroups(t, idp)
	idp.LogInAs(authtest.User{Email: "jane@example.com", EmailVerified: true, Groups: []string{"platform", "payments"}})

	identity, _, err := o.FinishLogin(httptest.NewRecorder(), login(t, o, "/"))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if want := []string{"payments", "platform"}; !slices.Equal(identity.Groups, want) {
		t.Errorf("Groups = %q, want %q", identity.Groups, want)
	}

	// Without the claim configured, no groups are read.
	plain := newOIDC(t, idp)
	identity, _, err = plain.FinishLogin(httptest.NewRecorder(), login(t, plain, "/"))
	if err != nil || identity.Groups != nil {
		t.Errorf("groups without the claim configured: %+v, %v", identity, err)
	}
}

func TestOIDCLoginFailures(t *testing.T) {
	idp := authtest.New(t)
	o := newOIDC(t, idp)

	t.Run("no login cookie", func(t *testing.T) {
		callback := login(t, o, "/")
		bare := httptest.NewRequest(http.MethodGet, callback.URL.String(), nil)
		_, _, err := o.FinishLogin(httptest.NewRecorder(), bare)
		if p, ok := problem.As(err); !ok || !strings.Contains(p.Message, "log in again") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("state from another login", func(t *testing.T) {
		first := login(t, o, "/")
		second := login(t, o, "/")
		mixed := httptest.NewRequest(http.MethodGet, first.URL.String(), nil)
		for _, c := range second.Cookies() {
			mixed.AddCookie(c)
		}
		if _, _, err := o.FinishLogin(httptest.NewRecorder(), mixed); err == nil {
			t.Error("a callback with another login's cookie was accepted")
		}
	})
	t.Run("code used twice", func(t *testing.T) {
		callback := login(t, o, "/")
		if _, _, err := o.FinishLogin(httptest.NewRecorder(), callback); err != nil {
			t.Fatal(err)
		}
		if _, _, err := o.FinishLogin(httptest.NewRecorder(), callback); err == nil {
			t.Error("a login code worked twice")
		}
	})
	t.Run("provider refused", func(t *testing.T) {
		callback := login(t, o, "/")
		refused := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&state=x", nil)
		for _, c := range callback.Cookies() {
			refused.AddCookie(c)
		}
		if _, _, err := o.FinishLogin(httptest.NewRecorder(), refused); err == nil {
			t.Error("a refused login was accepted")
		}
	})
	t.Run("unverified email", func(t *testing.T) {
		idp.LogInAs(authtest.User{Email: "jane@example.com", EmailVerified: false})
		defer idp.LogInAs(authtest.User{Email: "jane@example.com", EmailVerified: true})
		if _, _, err := o.FinishLogin(httptest.NewRecorder(), login(t, o, "/")); err == nil {
			t.Error("an unverified email address was accepted")
		}
	})
}

func TestSafeReturnPath(t *testing.T) {
	tests := map[string]string{
		"/ssm?q=x":            "/ssm?q=x",
		"":                    "/",
		"https://evil.com":    "/",
		"//evil.com/x":        "/",
		"/\\evil.com":         "/",
		"/auth/callback?code": "/",
	}
	for in, want := range tests {
		if got := auth.SafeReturnPath(in); got != want {
			t.Errorf("SafeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}
