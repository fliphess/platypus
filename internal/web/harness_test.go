package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"platypus/internal/seal"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"platypus/internal/access"
	"platypus/internal/appstate"
	"platypus/internal/audit"
	"platypus/internal/auth"
	"platypus/internal/auth/authtest"
	"platypus/internal/bootstrap"
	"platypus/internal/catalog"
	"platypus/internal/config"
	"platypus/internal/database/dbtest"
	"platypus/internal/db"
	"platypus/internal/docs"
	"platypus/internal/items"
	"platypus/internal/lockout"
	"platypus/internal/mfa"
	"platypus/internal/ratelimit"
	"platypus/internal/sensitive"
	"platypus/internal/session"
	"platypus/internal/store"
	"platypus/internal/store/memstore"
)

const tokenParam = "/platypus/bootstrap-token"

// harness runs the real web server against a real database and the
// in-memory AWS fake. Each user gets their own cookie jar, like a browser.
type harness struct {
	t       *testing.T
	srv     *httptest.Server
	pool    *pgxpool.Pool
	q       *db.Queries
	params  *memstore.Parameters
	secrets *memstore.Secrets
	catalog *catalog.Catalog
	access  *access.Service
	logs    *bytes.Buffer
	clients map[string]*http.Client
	server  *Server
	// groups is the groups header value sent for an email (header mode).
	groups map[string]string
}

// harnessSetup is what harness options can change.
type harnessSetup struct {
	settings    Settings
	auth        func(h *harness) (auth.RequestVerifier, *auth.OIDC)
	idleTimeout time.Duration
}

// harnessOption changes the setup of a harness.
type harnessOption func(*harnessSetup)

func withoutPasskeys(s *harnessSetup) { s.settings.PasskeysEnabled = false }

// withSessionIdle makes sessions (and oidc logins) end after d without requests.
func withSessionIdle(d time.Duration) harnessOption {
	return func(s *harnessSetup) { s.idleTimeout = d }
}

// withHeaderGroups runs the harness in header mode, also reading the
// groups header the login proxy would set.
func withHeaderGroups(s *harnessSetup) {
	s.auth = func(*harness) (auth.RequestVerifier, *auth.OIDC) {
		return auth.NewHeader("X-Auth-Request-Email", "X-Auth-Request-Groups"), nil
	}
}

// withSignedHeader runs the harness in signed-header mode with tokens from idp.
func withSignedHeader(idp *authtest.Provider) harnessOption {
	return func(s *harnessSetup) {
		s.auth = func(*harness) (auth.RequestVerifier, *auth.OIDC) {
			return auth.NewSignedHeader(context.Background(), config.SignedHeader{
				Name: signedHeader, JWKSURL: idp.JWKSURL(), Issuer: idp.Issuer(),
				Audience: signedAudience, EmailClaim: "email",
			}), nil
		}
	}
}

// withOIDC runs the harness in oidc mode against idp.
func withOIDC(idp *authtest.Provider) harnessOption {
	return func(s *harnessSetup) {
		s.auth = func(h *harness) (auth.RequestVerifier, *auth.OIDC) {
			sealer, _ := seal.New(sensitive.New(config.TestEncryptionKey))
			publicURL, _ := url.Parse(h.srv.URL)
			login, err := auth.NewOIDC(context.Background(), config.OIDC{
				Issuer: idp.Issuer(), ClientID: authtest.ClientID, ClientSecret: sensitive.New(authtest.ClientSecret),
				Scopes: []string{"openid", "email", "profile"}, EmailClaim: "email", GroupsClaim: "groups",
			}, publicURL, sealer, true)
			if err != nil {
				h.t.Fatalf("NewOIDC: %v", err)
			}
			return nil, login
		}
	}
}

const (
	signedHeader   = "X-Signed-Assertion"
	signedAudience = "platypus-test"
)

func newHarness(t *testing.T, options ...harnessOption) *harness {
	t.Helper()
	pool := dbtest.New(t)
	q := db.New(pool)

	logs := &bytes.Buffer{}
	log := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(logs), zap.DebugLevel))

	recorder := audit.NewRecorder(q, log)
	guard := lockout.NewGuard(q, recorder)
	limiter := ratelimit.New(q)
	cat := catalog.New(q)
	params := memstore.NewParameters()
	secrets := memstore.NewSecrets()

	sealer, err := seal.New(sensitive.New(config.TestEncryptionKey))
	if err != nil {
		t.Fatal(err)
	}
	publicURL, _ := url.Parse("https://platypus.example.com")
	mfaService, err := mfa.NewService(pool, sealer, publicURL, guard, recorder)
	if err != nil {
		t.Fatal(err)
	}
	library, err := docs.Load("../../internal/docs/pages")
	if err != nil {
		t.Fatal(err)
	}
	accessService := access.NewService(pool, recorder, []string{"example.com"})

	setup := harnessSetup{idleTimeout: time.Hour, auth: func(*harness) (auth.RequestVerifier, *auth.OIDC) {
		return auth.NewHeader("X-Auth-Request-Email", ""), nil
	}}
	setup.settings = Settings{
		AllowedEmailDomains: []string{"example.com"},
		AdminModeDuration:   15 * time.Minute,
		RevealHideAfter:     10 * time.Second,
		AuditRetentionDays:  365,
		BlockContactEmail:   "platform@example.com",
		BootstrapTokenParam: tokenParam,
		PasskeysEnabled:     true,
		TemplatesDir:        "templates",
		StaticDir:           "static",
	}
	for _, option := range options {
		option(&setup)
	}

	// The server starts first, so oidc mode knows its URL for the callback.
	var handler http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	h := &harness{
		t: t, srv: srv, pool: pool, q: q, params: params, secrets: secrets, catalog: cat,
		access: accessService, logs: logs, clients: map[string]*http.Client{}, groups: map[string]string{},
	}
	verifier, login := setup.auth(h)

	server, err := NewServer(Services{
		Auth:      verifier,
		Login:     login,
		Access:    accessService,
		AppState:  appstate.NewService(pool, recorder),
		Audit:     recorder,
		Trail:     audit.NewTrail(q, recorder),
		Bootstrap: bootstrap.NewService(pool, params, mfaService, guard, recorder, bootstrap.Config{TokenParam: tokenParam, TokenTTL: time.Hour}),
		Catalog:   cat,
		Items:     items.NewService(cat, params, secrets, recorder, limiter, items.Config{RevealsPerMinute: 100}),
		MFA:       mfaService,
		Sessions:  session.NewManager(q, setup.idleTimeout, 12*time.Hour, true),
		Docs:      library,
	}, setup.settings, log)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler = server.Handler()
	h.server = server
	return h
}

func (h *harness) client(email string) *http.Client {
	if c, ok := h.clients[email]; ok {
		return c
	}
	jar, _ := cookiejar.New(nil)
	c := h.srv.Client()
	c = &http.Client{Transport: c.Transport, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	h.clients[email] = c
	return c
}

type response struct {
	status int
	header http.Header
	body   string
}

// setGroups makes the harness send these identity-provider groups for every
// request of email, as the login proxy's groups header would.
func (h *harness) setGroups(email string, groups ...string) {
	h.groups[email] = strings.Join(groups, ",")
}

// do sends a request as email (no identity header when empty). htmx marks
// the request as coming from htmx, which most POSTs in the UI do.
func (h *harness) do(method, path, email string, form url.Values, htmx bool) response {
	h.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, h.srv.URL+path, body)
	if err != nil {
		h.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if email != "" {
		req.Header.Set("X-Auth-Request-Email", email)
		if groups, ok := h.groups[email]; ok {
			req.Header.Set("X-Auth-Request-Groups", groups)
		}
	}
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	if method == http.MethodPost && email != "" {
		req.Header.Set("X-CSRF-Token", h.csrf(email))
	}
	resp, err := h.client(email).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: string(data)}
}

func (h *harness) get(path, email string) response {
	h.t.Helper()
	return h.do(http.MethodGet, path, email, nil, false)
}

func (h *harness) post(path, email string, form url.Values) response {
	h.t.Helper()
	return h.do(http.MethodPost, path, email, form, true)
}

var csrfMeta = regexp.MustCompile(`name="csrf-token" content="([^"]+)"`)

// csrf returns the user's CSRF token by loading the docs page, which every
// logged-in user can open (bootstrap pages before setup).
func (h *harness) csrf(email string) string {
	h.t.Helper()
	path := "/docs"
	if state, _ := h.q.GetAppState(context.Background()); !state.Bootstrapped {
		path = "/bootstrap"
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	req.Header.Set("X-Auth-Request-Email", email)
	resp, err := h.client(email).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	match := csrfMeta.FindStringSubmatch(string(data))
	if match == nil {
		h.t.Fatalf("no CSRF token on %s for %s (status %d)", path, email, resp.StatusCode)
	}
	return match[1]
}

func (h *harness) expect(r response, status int) {
	h.t.Helper()
	if r.status != status {
		h.t.Fatalf("status %d, want %d; body:\n%s", r.status, status, r.body)
	}
}

var totpKey = regexp.MustCompile(`Key: <code>([A-Z2-7]+)</code>`)

// bootstrap completes setup through the UI as admin and returns the admin's
// TOTP secret.
func (h *harness) bootstrap() string {
	h.t.Helper()
	ctx := context.Background()
	token := h.issueToken()

	h.expect(h.post("/bootstrap/token", admin, url.Values{"token": {token}}), http.StatusOK)
	setup := h.post("/me/security/totp", admin, url.Values{})
	match := totpKey.FindStringSubmatch(setup.body)
	if match == nil {
		h.t.Fatalf("no TOTP key in:\n%s", setup.body)
	}
	secret := match[1]
	if !strings.Contains(setup.body, `src="data:image/png;base64,`) {
		h.t.Fatalf("the QR code is not shown:\n%s", setup.body)
	}
	h.expect(h.post("/me/security/totp/confirm", admin, url.Values{"code": {totpCode(h.t, secret, -30*time.Second)}}), http.StatusOK)
	h.expect(h.do(http.MethodPost, "/me/security/recovery-codes", admin, url.Values{}, false), http.StatusOK)
	h.expect(h.post("/bootstrap/complete", admin, url.Values{}), http.StatusOK)

	if state, _ := h.q.GetAppState(ctx); !state.Bootstrapped {
		h.t.Fatal("bootstrap did not complete")
	}
	return secret
}

// issueToken writes a bootstrap token like the worker does and returns it.
func (h *harness) issueToken() string {
	h.t.Helper()
	ctx := context.Background()
	recorder := audit.NewRecorder(h.q, zap.NewNop())
	guard := lockout.NewGuard(h.q, recorder)
	sealer, _ := seal.New(sensitive.New(config.TestEncryptionKey))
	publicURL, _ := url.Parse("https://platypus.example.com")
	mfaService, _ := mfa.NewService(h.pool, sealer, publicURL, guard, recorder)
	svc := bootstrap.NewService(h.pool, h.params, mfaService, guard, recorder, bootstrap.Config{TokenParam: tokenParam, TokenTTL: time.Hour})
	if _, err := svc.EnsureToken(ctx); err != nil {
		h.t.Fatal(err)
	}
	value, err := h.params.Value(ctx, tokenParam, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	return value.Reveal()
}

// elevate switches on admin mode for admin with the current TOTP code.
func (h *harness) elevate(secret string) {
	h.t.Helper()
	r := h.post("/admin/elevate/totp", admin, url.Values{"code": {totpCode(h.t, secret, 0)}})
	h.expect(r, http.StatusOK)
	if !strings.Contains(r.header.Get("HX-Redirect"), "admin-on") {
		h.t.Fatalf("admin mode not started: %v\n%s", r.header, r.body)
	}
}

func totpCode(t *testing.T, secret string, offset time.Duration) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().Add(offset))
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// addParameter creates a parameter in the fake AWS and the catalog.
func (h *harness) addParameter(name, value string) {
	h.t.Helper()
	ctx := context.Background()
	p, err := h.params.Create(ctx, store.NewParameter{Name: name, Value: sensitive.New(value), Type: "SecureString", Tier: "Standard"})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.catalog.PutParameter(ctx, p, catalog.AccessOK, time.Now()); err != nil {
		h.t.Fatal(err)
	}
}

// addSecret creates a secret in the fake AWS and the catalog.
func (h *harness) addSecret(name, value string) {
	h.t.Helper()
	ctx := context.Background()
	s, err := h.secrets.Create(ctx, store.NewSecret{Name: name, Value: sensitive.New(value)})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.catalog.PutSecret(ctx, s, catalog.AccessOK, time.Now()); err != nil {
		h.t.Fatal(err)
	}
}

// grant gives user a policy with the given rules, assigned directly. It
// replaces what earlier grants gave the same user.
func (h *harness) grant(user string, rules ...access.RuleInput) {
	h.t.Helper()
	ctx := audit.WithActor(context.Background(), audit.Actor{Email: "test"})
	u, err := h.access.UserForLogin(ctx, user, "", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	policy, err := h.access.CreatePolicy(ctx, access.PolicyInput{Name: "policy for " + user + " " + time.Now().String(), Rules: rules})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.access.SetUserPolicies(ctx, u.ID, []int64{policy.ID}); err != nil {
		h.t.Fatal(err)
	}
}

func dbListAll() db.ListAuditEventsParams {
	return db.ListAuditEventsParams{MaxRows: 1000}
}
