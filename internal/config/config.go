// Package config loads platypus settings from environment variables.
// There is no config file: every setting is listed in Vars.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"platypus/internal/item"
	"platypus/internal/sensitive"
)

// Environments platypus can run in.
const (
	EnvLocal      = "local"
	EnvCI         = "ci"
	EnvAcceptance = "acc"
	EnvProduction = "prd"
)

// TestEncryptionKey is the publicly known key used by docker-compose and tests.
// Load refuses it outside test mode.
const TestEncryptionKey = "cGxhdHlwdXMtdGVzdC1rZXktbm90LWZvci1wcm9kISE="

// exampleEncryptionKeys are keys published in the chart examples. They are
// refused outside test mode like the test key: copying an example is not a
// reason to deploy with a known key.
var exampleEncryptionKeys = []string{
	"cGxhdHlwdXMtY2hhcnQtZXhhbXBsZS1ub3QtcmVhbCE=",
}

// Config holds all settings.
type Config struct {
	Environment     string
	TestMode        bool
	TestAWSEndpoint string

	HTTPAddr        string
	HealthAddr      string
	PublicURL       *url.URL
	LogLevel        string
	ShutdownTimeout time.Duration

	Database Database

	Auth                Auth
	AllowedEmailDomains []string

	EncryptionKey sensitive.Value
	SSMKMSKeyID   string

	BootstrapTokenParam string
	BootstrapTokenTTL   time.Duration

	AdminModeDuration  time.Duration
	SessionIdleTimeout time.Duration
	SessionMaxAge      time.Duration

	RevealHideAfter  time.Duration
	RevealsPerMinute int

	PasskeysEnabled bool
	TerraformTags   []item.Tag

	SyncInterval          time.Duration
	SyncTimeout           time.Duration
	AccessRecheckInterval time.Duration

	AuditRetentionDays int
	BlockContactEmail  string
	DocsDir            string
	TemplatesDir       string
	StaticDir          string
}

// Authentication modes.
const (
	AuthHeader       = "header"
	AuthSignedHeader = "signed-header"
	AuthOIDC         = "oidc"
)

// Auth holds how people log in; only the settings of Mode are used.
type Auth struct {
	Mode           string
	IdentityHeader string
	// GroupsHeader names the header with the user's groups in header mode;
	// empty switches group mapping off.
	GroupsHeader string
	SignedHeader SignedHeader
	OIDC         OIDC
}

// SignedHeader holds the settings of signed-header mode.
type SignedHeader struct {
	Name       string
	JWKSURL    string
	Issuer     string
	Audience   string
	EmailClaim string
	// GroupsClaim names the claim with the user's groups; empty switches group
	// mapping off.
	GroupsClaim string
}

// OIDC holds the settings of oidc mode.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret sensitive.Value
	Scopes       []string
	EmailClaim   string
	// GroupsClaim names the ID token claim with the user's groups; empty
	// switches group mapping off.
	GroupsClaim string
	Prompt      string
}

// Database holds the Postgres connection settings.
type Database struct {
	Host     string
	Port     int
	Name     string
	Username string
	Password sensitive.Value
	Schema   string
	SSLMode  string
	// SSLRootCert is a file with the certificate authorities to trust.
	SSLRootCert string
	MaxConns    int
}

// SecureCookies reports whether cookies must carry the Secure flag. Only a
// test-mode setup on plain http may do without.
func (c Config) SecureCookies() bool {
	return c.PublicURL.Scheme == "https"
}

// Load reads the configuration through getenv (os.Getenv in production) and
// validates it. All problems are reported together.
func Load(getenv func(string) string) (Config, error) {
	r := reader{getenv: getenv}

	cfg := Config{
		Environment:     r.oneOf(varEnvironment, EnvLocal, EnvCI, EnvAcceptance, EnvProduction),
		TestMode:        r.bool(varTestMode),
		TestAWSEndpoint: r.string(varTestAWSEndpoint),

		HTTPAddr:        r.string(varHTTPAddr),
		HealthAddr:      r.string(varHealthAddr),
		PublicURL:       r.url(varPublicURL),
		LogLevel:        r.oneOf(varLogLevel, "debug", "info", "warn", "error"),
		ShutdownTimeout: r.duration(varShutdownTimeout),

		Database: Database{
			Host:     r.string(varDBHost),
			Port:     r.int(varDBPort),
			Name:     r.string(varDBName),
			Username: r.string(varDBUsername),
			Password: r.secret(varDBPassword),
			Schema:   r.string(varDBSchema),
			SSLMode:  r.oneOf(varDBSSLMode, "disable", "require", "verify-ca", "verify-full"),

			SSLRootCert: r.string(varDBSSLRootCert),
			MaxConns:    r.int(varDBMaxConns),
		},

		Auth: Auth{
			Mode:           r.oneOf(varAuthMode, AuthHeader, AuthSignedHeader, AuthOIDC),
			IdentityHeader: r.string(varIdentityHeader),
			GroupsHeader:   r.string(varGroupsHeader),
			SignedHeader: SignedHeader{
				Name:        r.string(varSignedHeader),
				JWKSURL:     r.string(varSignedHeaderJWKSURL),
				Issuer:      r.string(varSignedHeaderIssuer),
				Audience:    r.string(varSignedHeaderAudience),
				EmailClaim:  r.string(varSignedHeaderEmailClaim),
				GroupsClaim: r.string(varSignedHeaderGroupsClaim),
			},
			OIDC: OIDC{
				Issuer:       r.string(varOIDCIssuer),
				ClientID:     r.string(varOIDCClientID),
				ClientSecret: r.secret(varOIDCClientSecret),
				Scopes:       r.rawList(varOIDCScopes),
				EmailClaim:   r.string(varOIDCEmailClaim),
				GroupsClaim:  r.string(varOIDCGroupsClaim),
				Prompt:       r.string(varOIDCPrompt),
			},
		},
		AllowedEmailDomains: r.list(varAllowedEmailDomains),

		EncryptionKey: r.secret(varEncryptionKey),
		SSMKMSKeyID:   r.string(varSSMKMSKeyID),

		BootstrapTokenParam: r.string(varBootstrapTokenParam),
		BootstrapTokenTTL:   r.duration(varBootstrapTokenTTL),

		AdminModeDuration:  r.duration(varAdminModeDuration),
		SessionIdleTimeout: r.duration(varSessionIdleTimeout),
		SessionMaxAge:      r.duration(varSessionMaxAge),

		RevealHideAfter:  r.duration(varRevealHideAfter),
		RevealsPerMinute: r.int(varRevealsPerMinute),

		PasskeysEnabled: r.bool(varPasskeysEnabled),
		TerraformTags:   r.tags(varTerraformTags),

		SyncInterval:          r.duration(varSyncInterval),
		SyncTimeout:           r.duration(varSyncTimeout),
		AccessRecheckInterval: r.duration(varAccessRecheckInterval),

		AuditRetentionDays: r.int(varAuditRetentionDays),
		BlockContactEmail:  r.string(varBlockContactEmail),
		DocsDir:            r.string(varDocsDir),
		TemplatesDir:       r.string(varTemplatesDir),
		StaticDir:          r.string(varStaticDir),
	}

	errs := r.errs
	if len(errs) == 0 {
		errs = cfg.validate()
	}
	if len(errs) > 0 {
		return Config{}, fmt.Errorf("invalid configuration:\n  %w", errors.Join(errs...))
	}
	return cfg, nil
}

// validate checks rules that involve more than one setting.
func (c Config) validate() []error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	isDeployed := c.Environment == EnvAcceptance || c.Environment == EnvProduction
	if c.TestMode && isDeployed {
		add("%s is not allowed in %s", varTestMode.Name, c.Environment)
	}

	if c.TestMode {
		endpoint, err := url.Parse(c.TestAWSEndpoint)
		switch {
		case c.TestAWSEndpoint == "":
			add("%s is required in test mode", varTestAWSEndpoint.Name)
		case err != nil || endpoint.Host == "":
			add("%s must be a URL", varTestAWSEndpoint.Name)
		case strings.HasSuffix(endpoint.Hostname(), "amazonaws.com"):
			add("%s must point at a local emulator, not AWS", varTestAWSEndpoint.Name)
		}
	}

	// Compare decoded bytes: base64 decoders ignore line breaks, so the same
	// public key spelled across two lines must be refused just the same.
	configuredKey, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(c.EncryptionKey.Reveal()))
	if !c.TestMode {
		if c.PublicURL.Scheme != "https" {
			add("%s must use https outside test mode", varPublicURL.Name)
		}
		if c.Database.SSLMode == "disable" {
			add("%s=disable is only allowed in test mode", varDBSSLMode.Name)
		}
		if bytes.Equal(configuredKey, decodedKey(TestEncryptionKey)) {
			add("%s is the public test key, which is only allowed in test mode", varEncryptionKey.Name)
		}
		for _, example := range exampleEncryptionKeys {
			if bytes.Equal(configuredKey, decodedKey(example)) {
				add("%s is a published example key; generate one with openssl rand -base64 32", varEncryptionKey.Name)
			}
		}
	}

	errs = append(errs, c.validateAuth()...)

	if c.Database.MaxConns < 2 {
		add("%s must be at least 2", varDBMaxConns.Name)
	}
	if key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.EncryptionKey.Reveal())); err != nil || len(key) != 32 {
		add("%s must be 32 bytes, base64-encoded", varEncryptionKey.Name)
	} else if bytes.Count(key, key[:1]) == len(key) {
		add("%s is one byte repeated; generate it with openssl rand -base64 32", varEncryptionKey.Name)
	}

	for _, domain := range c.AllowedEmailDomains {
		if strings.ContainsAny(domain, "@ ") || !strings.Contains(domain, ".") {
			add("%s contains %q, which is not a domain", varAllowedEmailDomains.Name, domain)
		}
	}

	if c.HTTPAddr == c.HealthAddr {
		add("%s and %s must differ", varHTTPAddr.Name, varHealthAddr.Name)
	}
	if c.Database.Port <= 0 || c.Database.Port > 65535 {
		add("%s must be a port number", varDBPort.Name)
	}
	if c.RevealsPerMinute < 1 {
		add("%s must be at least 1", varRevealsPerMinute.Name)
	}
	if c.AuditRetentionDays < 0 {
		add("%s can't be negative", varAuditRetentionDays.Name)
	}
	if c.SessionIdleTimeout > c.SessionMaxAge {
		add("%s can't be longer than %s", varSessionIdleTimeout.Name, varSessionMaxAge.Name)
	}

	positive := map[string]time.Duration{
		varShutdownTimeout.Name:       c.ShutdownTimeout,
		varBootstrapTokenTTL.Name:     c.BootstrapTokenTTL,
		varAdminModeDuration.Name:     c.AdminModeDuration,
		varSessionIdleTimeout.Name:    c.SessionIdleTimeout,
		varSessionMaxAge.Name:         c.SessionMaxAge,
		varRevealHideAfter.Name:       c.RevealHideAfter,
		varSyncInterval.Name:          c.SyncInterval,
		varSyncTimeout.Name:           c.SyncTimeout,
		varAccessRecheckInterval.Name: c.AccessRecheckInterval,
	}
	for _, name := range slices.Sorted(maps.Keys(positive)) {
		if positive[name] <= 0 {
			add("%s must be positive", name)
		}
	}

	return errs
}

// validateAuth checks that the chosen authentication mode has what it needs.
func (c Config) validateAuth() []error {
	var errs []error
	require := func(v Var, value string) {
		if value == "" {
			errs = append(errs, fmt.Errorf("%s is required in %s mode", v.Name, c.Auth.Mode))
		}
	}
	requireURL := func(v Var, value string) {
		require(v, value)
		if value == "" {
			return
		}
		parsed, err := url.Parse(value)
		switch {
		case err != nil || parsed.Host == "":
			errs = append(errs, fmt.Errorf("%s must be a URL", v.Name))
		case parsed.Scheme != "https" && !c.TestMode:
			errs = append(errs, fmt.Errorf("%s must use https outside test mode", v.Name))
		}
	}

	switch c.Auth.Mode {
	case AuthHeader:
		require(varIdentityHeader, c.Auth.IdentityHeader)
	case AuthSignedHeader:
		require(varSignedHeader, c.Auth.SignedHeader.Name)
		requireURL(varSignedHeaderJWKSURL, c.Auth.SignedHeader.JWKSURL)
		require(varSignedHeaderIssuer, c.Auth.SignedHeader.Issuer)
		require(varSignedHeaderAudience, c.Auth.SignedHeader.Audience)
		require(varSignedHeaderEmailClaim, c.Auth.SignedHeader.EmailClaim)
	case AuthOIDC:
		requireURL(varOIDCIssuer, c.Auth.OIDC.Issuer)
		require(varOIDCClientID, c.Auth.OIDC.ClientID)
		require(varOIDCClientSecret, c.Auth.OIDC.ClientSecret.Reveal())
		require(varOIDCEmailClaim, c.Auth.OIDC.EmailClaim)
		if !slices.Contains(c.Auth.OIDC.Scopes, "openid") {
			errs = append(errs, fmt.Errorf("%s must include openid", varOIDCScopes.Name))
		}
	}
	return errs
}

// decodedKey returns the bytes a base64 key denotes. A malformed key decodes
// to nil and is reported by the length check.
func decodedKey(encoded string) []byte {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	return key
}
