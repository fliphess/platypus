package config

import (
	"maps"
	"os"
	"strings"
	"testing"
	"time"
)

// productionEnv returns a valid configuration for a deployed environment.
func productionEnv() map[string]string {
	return map[string]string{
		"PLATYPUS_ENVIRONMENT":           "prd",
		"PLATYPUS_AUTH_MODE":             "header",
		"PLATYPUS_PUBLIC_URL":            "https://platypus.example.com",
		"PLATYPUS_DB_HOST":               "db.example.com",
		"PLATYPUS_DB_NAME":               "platypus",
		"PLATYPUS_DB_USERNAME":           "platypus_rw",
		"PLATYPUS_DB_PASSWORD":           "hunter2",
		"PLATYPUS_ALLOWED_EMAIL_DOMAINS": "Example.com, example.org",
		"PLATYPUS_ENCRYPTION_KEY":        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
}

// testModeEnv returns a valid configuration for docker-compose.
func testModeEnv() map[string]string {
	env := productionEnv()
	env["PLATYPUS_ENVIRONMENT"] = "local"
	env["PLATYPUS_TEST_MODE"] = "true"
	env["PLATYPUS_TEST_AWS_ENDPOINT"] = "http://ministack:4566"
	env["PLATYPUS_PUBLIC_URL"] = "http://localhost:8080"
	env["PLATYPUS_DB_SSLMODE"] = "disable"
	env["PLATYPUS_ENCRYPTION_KEY"] = TestEncryptionKey
	return env
}

func load(env map[string]string) (Config, error) {
	return Load(func(name string) string { return env[name] })
}

func TestLoadProduction(t *testing.T) {
	cfg, err := load(productionEnv())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Environment != EnvProduction || cfg.TestMode {
		t.Errorf("environment = %q, test mode = %v", cfg.Environment, cfg.TestMode)
	}
	if got := cfg.PublicURL.String(); got != "https://platypus.example.com" {
		t.Errorf("public URL = %q", got)
	}
	if !cfg.SecureCookies() {
		t.Error("https should mean secure cookies")
	}
	if want := []string{"example.com", "example.org"}; strings.Join(cfg.AllowedEmailDomains, ",") != strings.Join(want, ",") {
		t.Errorf("allowed domains = %v, want %v", cfg.AllowedEmailDomains, want)
	}
	if cfg.Database.Port != 5432 || cfg.Database.Schema != "platypus" || cfg.Database.SSLMode != "verify-full" || cfg.Database.MaxConns != 10 {
		t.Errorf("database defaults not applied: %+v", cfg.Database)
	}
	if cfg.Database.Password.Reveal() != "hunter2" {
		t.Error("database password not read")
	}
	if cfg.AdminModeDuration != 15*time.Minute || cfg.AuditRetentionDays != 365 {
		t.Errorf("defaults not applied: admin mode %v, retention %d", cfg.AdminModeDuration, cfg.AuditRetentionDays)
	}
	if cfg.HTTPAddr == cfg.HealthAddr {
		t.Error("health checks must listen on their own address")
	}
}

func TestLoadTestMode(t *testing.T) {
	cfg, err := load(testModeEnv())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.TestMode || cfg.SecureCookies() {
		t.Errorf("test mode = %v, secure cookies = %v", cfg.TestMode, cfg.SecureCookies())
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name    string
		base    func() map[string]string
		change  map[string]string
		wantErr string
	}{
		{
			name:    "missing required variable",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_DB_HOST": ""},
			wantErr: "PLATYPUS_DB_HOST is required",
		},
		{
			name:    "unknown environment",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_ENVIRONMENT": "staging"},
			wantErr: "PLATYPUS_ENVIRONMENT must be one of",
		},
		{
			name:    "test mode in production",
			base:    testModeEnv,
			change:  map[string]string{"PLATYPUS_ENVIRONMENT": "prd"},
			wantErr: "PLATYPUS_TEST_MODE is not allowed in prd",
		},
		{
			name:    "test mode in acceptance",
			base:    testModeEnv,
			change:  map[string]string{"PLATYPUS_ENVIRONMENT": "acc"},
			wantErr: "PLATYPUS_TEST_MODE is not allowed in acc",
		},
		{
			name:    "test mode without emulator",
			base:    testModeEnv,
			change:  map[string]string{"PLATYPUS_TEST_AWS_ENDPOINT": ""},
			wantErr: "PLATYPUS_TEST_AWS_ENDPOINT is required in test mode",
		},
		{
			name:    "test mode pointing at real AWS",
			base:    testModeEnv,
			change:  map[string]string{"PLATYPUS_TEST_AWS_ENDPOINT": "https://ssm.eu-west-1.amazonaws.com"},
			wantErr: "must point at a local emulator",
		},
		{
			name:    "test encryption key outside test mode",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_ENCRYPTION_KEY": TestEncryptionKey},
			wantErr: "is the public test key",
		},
		{
			name:    "short encryption key",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_ENCRYPTION_KEY": "c2hvcnQ="},
			wantErr: "must be 32 bytes",
		},
		{
			name:    "plain http outside test mode",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_PUBLIC_URL": "http://platypus.example.com"},
			wantErr: "must use https outside test mode",
		},
		{
			name:    "public URL with a path",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_PUBLIC_URL": "https://example.com/platypus"},
			wantErr: "PLATYPUS_PUBLIC_URL must be a URL",
		},
		{
			name:    "unencrypted database outside test mode",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_DB_SSLMODE": "disable"},
			wantErr: "PLATYPUS_DB_SSLMODE=disable is only allowed in test mode",
		},
		{
			name:    "email address instead of domain",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_ALLOWED_EMAIL_DOMAINS": "me@example.com"},
			wantErr: "which is not a domain",
		},
		{
			name:    "health checks on the web port",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_HEALTH_ADDR": ":8080"},
			wantErr: "PLATYPUS_HTTP_ADDR and PLATYPUS_HEALTH_ADDR must differ",
		},
		{
			name:    "bad duration",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_ADMIN_MODE_DURATION": "15 minutes"},
			wantErr: "PLATYPUS_ADMIN_MODE_DURATION must be a duration",
		},
		{
			name:    "negative retention",
			base:    productionEnv,
			change:  map[string]string{"PLATYPUS_AUDIT_RETENTION_DAYS": "-1"},
			wantErr: "can't be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.base()
			maps.Copy(env, tt.change)
			_, err := load(env)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthModes(t *testing.T) {
	signed := productionEnv()
	maps.Copy(signed, map[string]string{
		"PLATYPUS_AUTH_MODE":              "signed-header",
		"PLATYPUS_SIGNED_HEADER":          "X-Goog-Iap-Jwt-Assertion",
		"PLATYPUS_SIGNED_HEADER_JWKS_URL": "https://www.gstatic.com/iap/verify/public_key-jwk",
		"PLATYPUS_SIGNED_HEADER_ISSUER":   "https://cloud.google.com/iap",
		"PLATYPUS_SIGNED_HEADER_AUDIENCE": "/projects/1/global/backendServices/2",
	})
	cfg, err := load(signed)
	if err != nil || cfg.Auth.SignedHeader.EmailClaim != "email" {
		t.Fatalf("signed-header: %+v, %v", cfg.Auth, err)
	}

	oidc := productionEnv()
	maps.Copy(oidc, map[string]string{
		"PLATYPUS_AUTH_MODE":          "oidc",
		"PLATYPUS_OIDC_ISSUER":        "https://accounts.google.com",
		"PLATYPUS_OIDC_CLIENT_ID":     "platypus",
		"PLATYPUS_OIDC_CLIENT_SECRET": "s3cret",
	})
	cfg, err = load(oidc)
	if err != nil || strings.Join(cfg.Auth.OIDC.Scopes, " ") != "openid email profile" {
		t.Fatalf("oidc: %+v, %v", cfg.Auth.OIDC.Scopes, err)
	}

	tests := []struct {
		name    string
		base    map[string]string
		change  map[string]string
		wantErr string
	}{
		{"no mode", productionEnv(), map[string]string{"PLATYPUS_AUTH_MODE": ""}, "PLATYPUS_AUTH_MODE is required"},
		{"unknown mode", productionEnv(), map[string]string{"PLATYPUS_AUTH_MODE": "saml"}, "must be one of"},
		{"signed-header without audience", signed, map[string]string{"PLATYPUS_SIGNED_HEADER_AUDIENCE": ""},
			"PLATYPUS_SIGNED_HEADER_AUDIENCE is required in signed-header mode"},
		{"keys over plain http", signed, map[string]string{"PLATYPUS_SIGNED_HEADER_JWKS_URL": "http://keys.example.com"},
			"must use https"},
		{"oidc without secret", oidc, map[string]string{"PLATYPUS_OIDC_CLIENT_SECRET": ""},
			"PLATYPUS_OIDC_CLIENT_SECRET is required in oidc mode"},
		{"oidc without openid scope", oidc, map[string]string{"PLATYPUS_OIDC_SCOPES": "email"}, "must include openid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := maps.Clone(tt.base)
			maps.Copy(env, tt.change)
			if _, err := load(env); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadAllowsZeroRetention(t *testing.T) {
	env := testModeEnv()
	env["PLATYPUS_AUDIT_RETENTION_DAYS"] = "0"
	cfg, err := load(env)
	if err != nil || cfg.AuditRetentionDays != 0 {
		t.Fatalf("retention 0 should be allowed for CI: cfg=%d err=%v", cfg.AuditRetentionDays, err)
	}
}

func TestLoadNeverPrintsSecrets(t *testing.T) {
	env := productionEnv()
	env["PLATYPUS_DB_PORT"] = "not-a-port"
	_, err := load(env)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), env["PLATYPUS_ENCRYPTION_KEY"]) {
		t.Fatalf("error leaks a secret: %v", err)
	}
}

// Every documented variable must be read by Load, and Load must not read
// variables that aren't documented.
func TestVarsMatchWhatLoadReads(t *testing.T) {
	read := map[string]bool{}
	_, _ = Load(func(name string) string {
		read[name] = true
		return testModeEnv()[name]
	})

	documented := map[string]bool{}
	for _, v := range Vars {
		if documented[v.Name] {
			t.Errorf("%s is listed twice in Vars", v.Name)
		}
		documented[v.Name] = true
		if !read[v.Name] {
			t.Errorf("%s is documented but never read", v.Name)
		}
		if v.Description == "" {
			t.Errorf("%s has no description", v.Name)
		}
	}
	for name := range read {
		if !documented[name] {
			t.Errorf("%s is read but missing from Vars", name)
		}
	}
}

func TestDocumentationFileIsUpToDate(t *testing.T) {
	onDisk, err := os.ReadFile("../docs/pages/90-configuration.txt")
	if err != nil {
		t.Fatalf("read docs: %v (run go generate ./internal/config)", err)
	}
	if string(onDisk) != Documentation() {
		t.Fatal("internal/docs/pages/90-configuration.txt is out of date: run go generate ./internal/config")
	}
}
