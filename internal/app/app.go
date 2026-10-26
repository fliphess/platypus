// Package app wires platypus together: it builds every service from the
// configuration and runs the web server, the worker or a one-off command.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"platypus/internal/seal"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/appstate"
	"platypus/internal/audit"
	"platypus/internal/auth"
	"platypus/internal/bootstrap"
	"platypus/internal/catalog"
	"platypus/internal/config"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/docs"
	"platypus/internal/health"
	"platypus/internal/items"
	"platypus/internal/itemsync"
	"platypus/internal/lockout"
	"platypus/internal/mfa"
	"platypus/internal/ratelimit"
	"platypus/internal/session"
	"platypus/internal/store/awsstore"
	"platypus/internal/web"
	"platypus/internal/worker"
)

// App holds the configured services.
type App struct {
	cfg  config.Config
	log  *zap.Logger
	pool *pgxpool.Pool

	queries    *db.Queries
	sealer     *seal.Sealer
	recorder   *audit.Recorder
	access     *access.Service
	appState   *appstate.Service
	catalog    *catalog.Catalog
	items      *items.Service
	mfa        *mfa.Service
	sessions   *session.Manager
	bootstrap  *bootstrap.Service
	limiter    *ratelimit.Limiter
	parameters *awsstore.Parameters
	secrets    *awsstore.Secrets
}

// New connects to Postgres and AWS and builds the services.
func New(ctx context.Context, cfg config.Config, log *zap.Logger) (*App, error) {
	pool, err := database.Connect(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}

	awsOptions := awsstore.Options{SSMKMSKeyID: cfg.SSMKMSKeyID}
	if cfg.TestMode {
		awsOptions.TestEndpoint = cfg.TestAWSEndpoint
	}
	parameters, secrets, err := awsstore.New(ctx, awsOptions)
	if err != nil {
		pool.Close()
		return nil, err
	}

	sealer, err := seal.New(cfg.EncryptionKey)
	if err != nil {
		pool.Close()
		return nil, err
	}

	queries := db.New(pool)
	recorder := audit.NewRecorder(queries, log)
	guard := lockout.NewGuard(queries, recorder)
	limiter := ratelimit.New(queries)
	cat := catalog.New(queries)

	var passkeyOrigin *url.URL
	if cfg.PasskeysEnabled {
		passkeyOrigin = cfg.PublicURL
	}
	mfaService, err := mfa.NewService(pool, sealer, passkeyOrigin, guard, recorder)
	if err != nil {
		pool.Close()
		return nil, err
	}

	return &App{
		cfg:      cfg,
		log:      log,
		pool:     pool,
		queries:  queries,
		sealer:   sealer,
		recorder: recorder,
		access:   access.NewService(pool, recorder, cfg.AllowedEmailDomains),
		appState: appstate.NewService(queries, recorder),
		catalog:  cat,
		items: items.NewService(cat, parameters, secrets, recorder, limiter, items.Config{
			RevealsPerMinute: cfg.RevealsPerMinute,
			TerraformTags:    cfg.TerraformTags,
		}),
		mfa:        mfaService,
		sessions:   session.NewManager(queries, cfg.SessionIdleTimeout, cfg.SessionMaxAge, cfg.SecureCookies()),
		bootstrap:  bootstrap.NewService(pool, parameters, mfaService, guard, recorder, bootstrap.Config{TokenParam: cfg.BootstrapTokenParam, TokenTTL: cfg.BootstrapTokenTTL}),
		limiter:    limiter,
		parameters: parameters,
		secrets:    secrets,
	}, nil
}

// Close releases the database connections.
func (a *App) Close() {
	a.pool.Close()
}

// RunWeb serves the user interface and the health checks until ctx ends.
func (a *App) RunWeb(ctx context.Context) error {
	library, err := docs.Load(a.cfg.DocsDir)
	if err != nil {
		return err
	}
	verifier, login, err := a.authentication(ctx)
	if err != nil {
		return err
	}
	server, err := web.NewServer(web.Services{
		Auth:      verifier,
		Login:     login,
		Access:    a.access,
		AppState:  a.appState,
		Audit:     a.recorder,
		Trail:     audit.NewTrail(a.queries, a.recorder),
		Bootstrap: a.bootstrap,
		Catalog:   a.catalog,
		Items:     a.items,
		MFA:       a.mfa,
		Sessions:  a.sessions,
		Docs:      library,
	}, web.Settings{
		AllowedEmailDomains: a.cfg.AllowedEmailDomains,
		AdminModeDuration:   a.cfg.AdminModeDuration,
		RevealHideAfter:     a.cfg.RevealHideAfter,
		AuditRetentionDays:  a.cfg.AuditRetentionDays,
		BlockContactEmail:   a.cfg.BlockContactEmail,
		BootstrapTokenParam: a.cfg.BootstrapTokenParam,
		PasskeysEnabled:     a.cfg.PasskeysEnabled,
		TestMode:            a.cfg.TestMode,
		TemplatesDir:        a.cfg.TemplatesDir,
		StaticDir:           a.cfg.StaticDir,
	}, a.log)
	if err != nil {
		return err
	}

	a.log.Info("starting web server", zap.String("addr", a.cfg.HTTPAddr), zap.String("health_addr", a.cfg.HealthAddr),
		zap.String("auth_mode", a.cfg.Auth.Mode),
		zap.String("environment", a.cfg.Environment), zap.Bool("test_mode", a.cfg.TestMode))
	return serve(ctx, a.cfg.ShutdownTimeout,
		newHTTPServer(a.cfg.HTTPAddr, server.Handler()),
		newHTTPServer(a.cfg.HealthAddr, health.Handler(a.pool, nil)))
}

// authentication builds the configured login method: a request verifier for
// the proxy modes, or the OIDC login.
func (a *App) authentication(ctx context.Context) (auth.RequestVerifier, *auth.OIDC, error) {
	switch a.cfg.Auth.Mode {
	case config.AuthHeader:
		return auth.NewHeader(a.cfg.Auth.IdentityHeader, a.cfg.Auth.GroupsHeader), nil, nil
	case config.AuthSignedHeader:
		return auth.NewSignedHeader(ctx, a.cfg.Auth.SignedHeader), nil, nil
	case config.AuthOIDC:
		login, err := a.discoverOIDC(ctx)
		return nil, login, err
	}
	return nil, nil, fmt.Errorf("unknown authentication mode %q", a.cfg.Auth.Mode)
}

// discoverOIDC sets up the OIDC login, retrying for a while: platypus may
// start before the identity provider is reachable, for example right after
// a cluster or network change.
func (a *App) discoverOIDC(ctx context.Context) (*auth.OIDC, error) {
	const attempts = 10
	for attempt := 1; ; attempt++ {
		login, err := auth.NewOIDC(ctx, a.cfg.Auth.OIDC, a.cfg.PublicURL, a.sealer, a.cfg.SecureCookies())
		if err == nil || attempt == attempts {
			return login, err
		}
		a.log.Warn("identity provider not reachable yet; retrying", zap.Int("attempt", attempt), zap.Error(err))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// RunWorker runs the background jobs and the health checks until ctx ends.
func (a *App) RunWorker(ctx context.Context) error {
	w := worker.New(a.pool,
		itemsync.NewJob(a.catalog, a.queries, a.parameters, a.secrets, a.log),
		a.bootstrap, a.sessions, a.limiter,
		worker.Config{SyncInterval: a.cfg.SyncInterval, SyncTimeout: a.cfg.SyncTimeout, AccessRecheckInterval: a.cfg.AccessRecheckInterval},
		a.log)

	healthServer := newHTTPServer(a.cfg.HealthAddr, health.Handler(a.pool, w.Alive))
	healthDone := make(chan error, 1)
	go func() { healthDone <- serve(ctx, a.cfg.ShutdownTimeout, healthServer) }()

	a.log.Info("starting worker", zap.String("health_addr", a.cfg.HealthAddr),
		zap.String("environment", a.cfg.Environment), zap.Bool("test_mode", a.cfg.TestMode))
	err := w.Run(ctx)
	return errors.Join(err, <-healthDone)
}

// ResetBootstrap puts platypus back into bootstrap mode and writes a new
// token to SSM. All data stays. Run it with kubectl exec.
func (a *App) ResetBootstrap(ctx context.Context) error {
	ctx = audit.WithActor(ctx, audit.ActorCLI)
	if err := a.bootstrap.Reset(ctx); err != nil {
		return err
	}
	a.log.Info("bootstrap reset: a new token is in SSM", zap.String("parameter", a.cfg.BootstrapTokenParam))
	return nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// serve runs the servers until ctx ends or one fails, then shuts all of them
// down gracefully.
func serve(ctx context.Context, shutdownTimeout time.Duration, servers ...*http.Server) error {
	errs := make(chan error, len(servers))
	var listenConfig net.ListenConfig
	for _, server := range servers {
		listener, err := listenConfig.Listen(ctx, "tcp", server.Addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", server.Addr, err)
		}
		go func() {
			if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("serve %s: %w", server.Addr, err)
			}
		}()
	}

	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errs:
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		failure = errors.Join(failure, server.Shutdown(shutdownCtx))
	}
	return failure
}
