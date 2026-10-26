package config

// Var describes one environment variable. The list below is the single source
// of truth: Load reads exactly these variables, and the configuration page in
// the docs is generated from them (see Documentation).
type Var struct {
	Name        string
	Default     string
	Required    bool
	Secret      bool
	Description string
}

var (
	varEnvironment = Var{
		Name:        "PLATYPUS_ENVIRONMENT",
		Required:    true,
		Description: "Where platypus runs: local, ci, acc or prd.",
	}
	varTestMode = Var{
		Name:    "PLATYPUS_TEST_MODE",
		Default: "false",
		Description: "Run against a local AWS emulator with fake credentials instead of real AWS. " +
			"Refused in acc and prd. Also allows plain http and the test encryption key.",
	}
	varTestAWSEndpoint = Var{
		Name: "PLATYPUS_TEST_AWS_ENDPOINT",
		Description: "URL of the local AWS emulator (for example http://ministack:4566). " +
			"Required in test mode, ignored otherwise. Must not point at amazonaws.com.",
	}
	varHTTPAddr = Var{
		Name:        "PLATYPUS_HTTP_ADDR",
		Default:     ":8080",
		Description: "Address the web server listens on.",
	}
	varHealthAddr = Var{
		Name:    "PLATYPUS_HEALTH_ADDR",
		Default: ":8081",
		Description: "Address of the separate health check listener (/healthz and /readyz) for the " +
			"Kubernetes probes. Never exposed through the Service or the gateway.",
	}
	varPublicURL = Var{
		Name:     "PLATYPUS_PUBLIC_URL",
		Required: true,
		Description: "The URL users open platypus on, for example https://platypus.example.internal. " +
			"Used for passkeys and cookies. Must be https outside test mode.",
	}
	varLogLevel = Var{
		Name:        "PLATYPUS_LOG_LEVEL",
		Default:     "info",
		Description: "Log level: debug, info, warn or error.",
	}
	varDBHost = Var{
		Name:        "PLATYPUS_DB_HOST",
		Required:    true,
		Description: "Postgres host.",
	}
	varDBPort = Var{
		Name:        "PLATYPUS_DB_PORT",
		Default:     "5432",
		Description: "Postgres port.",
	}
	varDBName = Var{
		Name:        "PLATYPUS_DB_NAME",
		Required:    true,
		Description: "Postgres database name.",
	}
	varDBUsername = Var{
		Name:        "PLATYPUS_DB_USERNAME",
		Required:    true,
		Description: "Postgres user for the application (read-write, no DDL rights needed).",
	}
	varDBPassword = Var{
		Name:        "PLATYPUS_DB_PASSWORD",
		Required:    true,
		Secret:      true,
		Description: "Postgres password for the application user.",
	}
	varDBSchema = Var{
		Name:        "PLATYPUS_DB_SCHEMA",
		Default:     "platypus",
		Description: "Postgres schema holding the platypus tables (created by the Flyway migrations).",
	}
	varDBSSLMode = Var{
		Name:    "PLATYPUS_DB_SSLMODE",
		Default: "verify-full",
		Description: "Postgres sslmode: disable, require, verify-ca or verify-full. require encrypts but doesn't check " +
			"who answers; disable is only allowed in test mode.",
	}
	varDBSSLRootCert = Var{
		Name: "PLATYPUS_DB_SSLROOTCERT",
		Description: "File with the certificate authorities that sign the database server's certificate, for " +
			"verify-ca and verify-full. For RDS: the AWS RDS certificate bundle. Empty uses the system's.",
	}
	varDBMaxConns = Var{
		Name:        "PLATYPUS_DB_MAX_CONNS",
		Default:     "10",
		Description: "Maximum number of database connections per process.",
	}
	varAuthMode = Var{
		Name:     "PLATYPUS_AUTH_MODE",
		Required: true,
		Description: "How people log in. header: a login proxy (for example oauth2-proxy) sets a header with " +
			"the user's email; the gateway must strip it from incoming requests. signed-header: a login proxy " +
			"sends a signed token (JWT) that platypus verifies. oidc: platypus logs people in itself with OpenID " +
			"Connect. See docs/60-security.txt.",
	}
	varIdentityHeader = Var{
		Name:    "PLATYPUS_IDENTITY_HEADER",
		Default: "X-Auth-Request-Email",
		Description: "header mode: the request header holding the email address of the logged-in user, set by " +
			"the login proxy. The gateway must strip this header from incoming requests.",
	}
	varGroupsHeader = Var{
		Name: "PLATYPUS_GROUPS_HEADER",
		Description: "header mode: the request header holding the user's identity-provider groups as a " +
			"comma-separated list, for example X-Auth-Request-Groups (oauth2-proxy). The gateway must strip " +
			"this header from incoming requests. Empty (the default) switches group mapping off.",
	}
	varSignedHeader = Var{
		Name: "PLATYPUS_SIGNED_HEADER",
		Description: "signed-header mode: the request header holding the signed token, for example " +
			"X-Goog-Iap-Jwt-Assertion (Google IAP), Cf-Access-Jwt-Assertion (Cloudflare Access), " +
			"X-Pomerium-Jwt-Assertion (Pomerium) or Authorization (oauth2-proxy passing the ID token).",
	}
	varSignedHeaderJWKSURL = Var{
		Name:        "PLATYPUS_SIGNED_HEADER_JWKS_URL",
		Description: "signed-header mode: URL of the public keys (JWKS) the tokens are signed with.",
	}
	varSignedHeaderIssuer = Var{
		Name:        "PLATYPUS_SIGNED_HEADER_ISSUER",
		Description: "signed-header mode: the issuer (iss) the tokens must have.",
	}
	varSignedHeaderAudience = Var{
		Name:        "PLATYPUS_SIGNED_HEADER_AUDIENCE",
		Description: "signed-header mode: the audience (aud) the tokens must have.",
	}
	varSignedHeaderEmailClaim = Var{
		Name:        "PLATYPUS_SIGNED_HEADER_EMAIL_CLAIM",
		Default:     "email",
		Description: "signed-header mode: the claim holding the user's email address.",
	}
	varSignedHeaderGroupsClaim = Var{
		Name: "PLATYPUS_SIGNED_HEADER_GROUPS_CLAIM",
		Description: "signed-header mode: the claim holding the user's identity-provider groups, for example " +
			"groups. Empty (the default) switches group mapping off.",
	}
	varOIDCIssuer = Var{
		Name: "PLATYPUS_OIDC_ISSUER",
		Description: "oidc mode: the issuer URL of the identity provider, for example https://accounts.google.com " +
			"or https://example.okta.com. Register PLATYPUS_PUBLIC_URL/auth/callback as redirect URL there.",
	}
	varOIDCClientID = Var{
		Name:        "PLATYPUS_OIDC_CLIENT_ID",
		Description: "oidc mode: the client ID platypus has at the identity provider.",
	}
	varOIDCClientSecret = Var{
		Name:        "PLATYPUS_OIDC_CLIENT_SECRET",
		Secret:      true,
		Description: "oidc mode: the client secret platypus has at the identity provider.",
	}
	varOIDCScopes = Var{
		Name:        "PLATYPUS_OIDC_SCOPES",
		Default:     "openid,email,profile",
		Description: "oidc mode: comma-separated scopes to request.",
	}
	varOIDCPrompt = Var{
		Name: "PLATYPUS_OIDC_PROMPT",
		Description: "oidc mode: sent as the prompt parameter to the identity provider. Use login to make people " +
			"enter their credentials again after an idle logout, instead of being signed back in silently by " +
			"their identity provider session. Empty leaves it to the identity provider.",
	}
	varOIDCEmailClaim = Var{
		Name:        "PLATYPUS_OIDC_EMAIL_CLAIM",
		Default:     "email",
		Description: "oidc mode: the claim in the ID token holding the user's email address.",
	}
	varOIDCGroupsClaim = Var{
		Name: "PLATYPUS_OIDC_GROUPS_CLAIM",
		Description: "oidc mode: the claim in the ID token holding the user's identity-provider groups, for " +
			"example groups (Okta, Entra ID, Dex). Empty (the default) switches group mapping off.",
	}
	varAllowedEmailDomains = Var{
		Name:        "PLATYPUS_ALLOWED_EMAIL_DOMAINS",
		Required:    true,
		Description: "Comma-separated email domains that may use platypus, for example example.com.",
	}
	varEncryptionKey = Var{
		Name:     "PLATYPUS_ENCRYPTION_KEY",
		Required: true,
		Secret:   true,
		Description: "Base64-encoded 32-byte key that encrypts TOTP secrets in the database. " +
			"Generate one with: openssl rand -base64 32",
	}
	varSSMKMSKeyID = Var{
		Name:        "PLATYPUS_SSM_KMS_KEY_ID",
		Description: "KMS key ID or alias used for new SecureString parameters. Empty uses the AWS managed key.",
	}
	varBootstrapTokenParam = Var{
		Name:        "PLATYPUS_BOOTSTRAP_TOKEN_PARAM",
		Default:     "/platypus/bootstrap-token",
		Description: "SSM parameter the bootstrap token is written to.",
	}
	varBootstrapTokenTTL = Var{
		Name:        "PLATYPUS_BOOTSTRAP_TOKEN_TTL",
		Default:     "24h",
		Description: "How long a bootstrap token stays valid.",
	}
	varAdminModeDuration = Var{
		Name:        "PLATYPUS_ADMIN_MODE_DURATION",
		Default:     "15m",
		Description: "How long admin mode lasts after confirming with TOTP or a passkey.",
	}
	varSessionIdleTimeout = Var{
		Name:    "PLATYPUS_SESSION_IDLE_TIMEOUT",
		Default: "10m",
		Description: "A platypus session ends after this long without requests. In oidc mode that logs the user " +
			"out; in the proxy modes it ends admin mode (the proxy controls the login itself).",
	}
	varSessionMaxAge = Var{
		Name:    "PLATYPUS_SESSION_MAX_AGE",
		Default: "12h",
		Description: "A platypus session ends this long after it started, active or not. In oidc mode the user " +
			"then logs in again.",
	}
	varRevealHideAfter = Var{
		Name:        "PLATYPUS_REVEAL_HIDE_AFTER",
		Default:     "10s",
		Description: "A revealed value is hidden again in the browser after this long.",
	}
	varPasskeysEnabled = Var{
		Name:    "PLATYPUS_PASSKEYS_ENABLED",
		Default: "true",
		Description: "Offer passkeys for admin mode. Passkeys need a browser that accepts the domain of " +
			"PLATYPUS_PUBLIC_URL; switch them off where it doesn't, such as local development.",
	}
	varTerraformTags = Var{
		Name:    "PLATYPUS_TERRAFORM_TAGS",
		Default: "Terraform=true",
		Description: "Comma-separated key=value tags that mark a parameter or secret as managed by Terraform. " +
			"Platypus shows those as such and refuses to change their value or description. Keys and values " +
			"match without regard to case.",
	}
	varRevealsPerMinute = Var{
		Name:        "PLATYPUS_REVEALS_PER_MINUTE",
		Default:     "30",
		Description: "Maximum number of reveals per user per minute.",
	}
	varSyncTimeout = Var{
		Name:    "PLATYPUS_SYNC_TIMEOUT",
		Default: "1h",
		Description: "How long one sync may take before the worker gives up on it. When the worker hasn't " +
			"finished a round of work for longer than this, its liveness check fails and Kubernetes restarts it.",
	}
	varSyncInterval = Var{
		Name:        "PLATYPUS_SYNC_INTERVAL",
		Default:     "5m",
		Description: "How often the worker refreshes the list of parameters and secrets from AWS.",
	}
	varAccessRecheckInterval = Var{
		Name:    "PLATYPUS_ACCESS_RECHECK_INTERVAL",
		Default: "24h",
		Description: "How often the worker re-checks whether platypus itself can access every parameter " +
			"and secret. Items platypus can't access are hidden.",
	}
	varAuditRetentionDays = Var{
		Name:    "PLATYPUS_AUDIT_RETENTION_DAYS",
		Default: "365",
		Description: "The admin prune button deletes audit events older than this many days. " +
			"0 deletes everything older than now.",
	}
	varBlockContactEmail = Var{
		Name:        "PLATYPUS_BLOCK_CONTACT_EMAIL",
		Description: "Email address shown to users while platypus is blocked.",
	}
	varDocsDir = Var{
		Name:        "PLATYPUS_DOCS_DIR",
		Default:     "docs",
		Description: "Directory holding the documentation text files shown in the app.",
	}
	varTemplatesDir = Var{
		Name:    "PLATYPUS_TEMPLATES_DIR",
		Default: "templates",
		Description: "Directory holding the HTML templates. Point it at your own set to change the interface " +
			"without rebuilding the binary.",
	}
	varStaticDir = Var{
		Name:        "PLATYPUS_STATIC_DIR",
		Default:     "static",
		Description: "Directory holding the files served under /static: the stylesheet, javascript and logo.",
	}
	varShutdownTimeout = Var{
		Name:        "PLATYPUS_SHUTDOWN_TIMEOUT",
		Default:     "15s",
		Description: "How long the server waits for running requests when shutting down.",
	}
)

// Vars lists every environment variable platypus reads, in documentation order.
var Vars = []Var{
	varEnvironment,
	varPublicURL,
	varHTTPAddr,
	varHealthAddr,
	varLogLevel,
	varShutdownTimeout,
	varDBHost,
	varDBPort,
	varDBName,
	varDBUsername,
	varDBPassword,
	varDBSchema,
	varDBSSLMode,
	varDBSSLRootCert,
	varDBMaxConns,
	varAuthMode,
	varAllowedEmailDomains,
	varIdentityHeader,
	varGroupsHeader,
	varSignedHeader,
	varSignedHeaderJWKSURL,
	varSignedHeaderIssuer,
	varSignedHeaderAudience,
	varSignedHeaderEmailClaim,
	varSignedHeaderGroupsClaim,
	varOIDCIssuer,
	varOIDCClientID,
	varOIDCClientSecret,
	varOIDCScopes,
	varOIDCEmailClaim,
	varOIDCGroupsClaim,
	varOIDCPrompt,
	varEncryptionKey,
	varSSMKMSKeyID,
	varBootstrapTokenParam,
	varBootstrapTokenTTL,
	varAdminModeDuration,
	varSessionIdleTimeout,
	varSessionMaxAge,
	varRevealHideAfter,
	varRevealsPerMinute,
	varPasskeysEnabled,
	varTerraformTags,
	varSyncInterval,
	varSyncTimeout,
	varAccessRecheckInterval,
	varAuditRetentionDays,
	varBlockContactEmail,
	varDocsDir,
	varTemplatesDir,
	varStaticDir,
	varTestMode,
	varTestAWSEndpoint,
}
