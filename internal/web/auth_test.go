package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"platypus/internal/auth/authtest"
)

// The header-mode tests are the rest of the web tests; these cover the
// other two modes.

func TestSignedHeaderMode(t *testing.T) {
	idp := authtest.New(t)
	h := newHarness(t, withSignedHeader(idp))
	if err := h.q.SetBootstrapped(context.Background(), true); err != nil {
		t.Fatal(err)
	}

	get := func(token string) response {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/me", nil)
		if token != "" {
			req.Header.Set(signedHeader, token)
		}
		// The plain identity header of header mode means nothing here.
		req.Header.Set("X-Auth-Request-Email", "admin@example.com")
		resp, err := h.client("signed").Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return response{status: resp.StatusCode, body: string(body)}
	}

	valid := get(idp.Sign(t, idp.Claims(signedAudience, "jane@example.com")))
	if valid.status != http.StatusOK || !strings.Contains(valid.body, "jane@example.com") {
		t.Fatalf("a valid token: %d", valid.status)
	}
	if user, _ := h.q.GetUserByEmail(context.Background(), "jane@example.com"); user.DisplayName != "Test User" {
		t.Errorf("the name from the token should fill the profile, got %q", user.DisplayName)
	}

	for name, token := range map[string]string{
		"no token":         "",
		"forged signature": idp.SignWithOtherKey(t, idp.Claims(signedAudience, "admin@example.com")),
		"wrong audience":   idp.Sign(t, idp.Claims("another-app", "admin@example.com")),
		"wrong domain":     idp.Sign(t, idp.Claims(signedAudience, "admin@other.org")),
	} {
		if r := get(token); r.status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, r.status)
		}
	}
}

func TestOIDCMode(t *testing.T) {
	idp := authtest.New(t)
	h := newHarness(t, withOIDC(idp))
	if err := h.q.SetBootstrapped(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	browser := h.client("browser")

	// Without a login, pages lead to the login, also with a forged header.
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/secrets?q=db", nil)
	req.Header.Set("X-Auth-Request-Email", "admin@example.com")
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/auth/login?return=%2Fsecrets%3Fq%3Ddb" {
		t.Fatalf("unauthenticated request: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	idp.LogInAs(authtest.User{Email: "Jane@Example.com", Name: "Jane Doe", EmailVerified: true})
	continuePage := h.oidcLogin(browser, "/secrets?q=db")
	if !strings.Contains(continuePage, `url=/secrets?q=db`) {
		t.Fatalf("after the login, the browser should continue to the page it wanted:\n%s", continuePage)
	}

	me := h.browse(browser, http.MethodGet, "/me", nil)
	if me.status != http.StatusOK || !strings.Contains(me.body, "jane@example.com") || !strings.Contains(me.body, "Log out") {
		t.Fatalf("logged in: %d\n%s", me.status, me.body)
	}
	if user, _ := h.q.GetUserByEmail(context.Background(), "jane@example.com"); user.DisplayName != "Jane Doe" {
		t.Errorf("profile name = %q, want the name from the identity provider", user.DisplayName)
	}

	// Logging out ends the session.
	csrf := csrfMeta.FindStringSubmatch(me.body)[1]
	out := h.browse(browser, http.MethodPost, "/auth/logout", url.Values{"csrf_token": {csrf}})
	if out.status != http.StatusSeeOther {
		t.Fatalf("logout: %d %s", out.status, out.body)
	}
	if again := h.browse(browser, http.MethodGet, "/me", nil); again.status != http.StatusSeeOther {
		t.Errorf("after logout /me = %d, want a redirect to the login", again.status)
	}
}

func TestOIDCIdleLogout(t *testing.T) {
	idp := authtest.New(t)
	h := newHarness(t, withOIDC(idp), withSessionIdle(time.Second))
	if err := h.q.SetBootstrapped(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	browser := h.client("browser")
	h.oidcLogin(browser, "/me")
	if r := h.browse(browser, http.MethodGet, "/me", nil); r.status != http.StatusOK {
		t.Fatalf("right after the login: %d", r.status)
	}
	time.Sleep(1500 * time.Millisecond)
	if r := h.browse(browser, http.MethodGet, "/me", nil); r.status != http.StatusSeeOther {
		t.Errorf("after the idle timeout: %d, want a redirect to the login", r.status)
	}
}

func TestOIDCRefusesOtherDomains(t *testing.T) {
	idp := authtest.New(t)
	h := newHarness(t, withOIDC(idp))
	idp.LogInAs(authtest.User{Email: "someone@other.org", EmailVerified: true})
	page := h.oidcLogin(h.client("browser"), "/")
	if !strings.Contains(page, "other.org can&#39;t use platypus") {
		t.Errorf("a login from another domain should be refused:\n%s", page)
	}
}

// oidcLogin walks the login as a browser would: platypus, the identity
// provider, back to the callback. It returns the callback's page.
func (h *harness) oidcLogin(browser *http.Client, returnTo string) string {
	h.t.Helper()
	next := h.srv.URL + "/auth/login?return=" + url.QueryEscape(returnTo)
	for range 5 {
		resp, err := browser.Get(next)
		if err != nil {
			h.t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		location := resp.Header.Get("Location")
		if location == "" {
			return string(body)
		}
		target, err := resp.Request.URL.Parse(location)
		if err != nil {
			h.t.Fatal(err)
		}
		next = target.String()
	}
	h.t.Fatal("too many redirects during the login")
	return ""
}

// browse sends a request as the given browser, without identity headers.
func (h *harness) browse(browser *http.Client, method, path string, form url.Values) response {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := browser.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: string(data)}
}
