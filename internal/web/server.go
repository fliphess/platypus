// Package web is the platypus user interface: server-rendered HTML with htmx.
//
// Every request passes the same chain (see Handler): request id, panic
// recovery, security headers, access log, identity from the gateway header,
// session, CSRF check and the application state gate. Handlers then only
// deal with their own work.
package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/appstate"
	"platypus/internal/audit"
	"platypus/internal/auth"
	"platypus/internal/bootstrap"
	"platypus/internal/catalog"
	"platypus/internal/docs"
	"platypus/internal/items"
	"platypus/internal/mfa"
	"platypus/internal/session"
)

// Services are the parts of platypus the web layer uses. Exactly one of
// Auth (header and signed-header mode) and Login (oidc mode) is set.
type Services struct {
	Auth      auth.RequestVerifier
	Login     *auth.OIDC
	Access    *access.Service
	AppState  *appstate.Service
	Audit     *audit.Recorder
	Trail     *audit.Trail
	Bootstrap *bootstrap.Service
	Catalog   *catalog.Catalog
	Items     *items.Service
	MFA       *mfa.Service
	Sessions  *session.Manager
	Docs      *docs.Library
}

// Settings are the web-specific settings.
type Settings struct {
	AllowedEmailDomains []string
	AdminModeDuration   time.Duration
	RevealHideAfter     time.Duration
	AuditRetentionDays  int
	BlockContactEmail   string
	BootstrapTokenParam string
	// PasskeysEnabled offers passkeys next to authenticator apps.
	PasskeysEnabled bool
	// TestMode shows a banner so nobody mistakes a test setup for the real one.
	TestMode bool
	// TemplatesDir holds the HTML templates and StaticDir the files served
	// under /static (css, javascript, logo). Both are read from disk, so a
	// deployment can change them without rebuilding.
	TemplatesDir string
	StaticDir    string
}

// Server handles HTTP requests.
type Server struct {
	services  Services
	settings  Settings
	templates *templates
	log       *zap.Logger
	now       func() time.Time
	// assetVersion changes whenever the static files do, so a browser can
	// never run a stale stylesheet or script after an update.
	assetVersion string
}

// assetVersion hashes the static files' names and modification times.
func assetVersion(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%s:%d\n", path, info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("read static files: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

// NewServer returns a Server.
func NewServer(services Services, settings Settings, log *zap.Logger) (*Server, error) {
	tmpl, err := loadTemplates(os.DirFS(settings.TemplatesDir))
	if err != nil {
		return nil, fmt.Errorf("templates directory %q: %w", settings.TemplatesDir, err)
	}
	info, err := os.Stat(settings.StaticDir)
	if err != nil {
		return nil, fmt.Errorf("static directory %q: %w", settings.StaticDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("static directory %q is not a directory", settings.StaticDir)
	}
	version, err := assetVersion(settings.StaticDir)
	if err != nil {
		return nil, err
	}
	return &Server{services: services, settings: settings, templates: tmpl, log: log, now: time.Now,
		assetVersion: version}, nil
}

// Handler returns the complete HTTP handler.
func (s *Server) Handler() http.Handler {
	root := http.NewServeMux()
	root.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(os.DirFS(s.settings.StaticDir)), !s.settings.TestMode)))
	// The login itself runs before anyone is identified.
	root.Handle("GET /auth/login", s.handle(s.startLogin))
	root.Handle("GET "+auth.CallbackPath, s.handle(s.finishLogin))
	root.Handle("GET /auth/logged-out", s.handle(s.loggedOut))
	root.Handle("/", s.withIdentity(s.withSession(s.withCSRF(s.withAppState(s.routes())))))

	return s.withRequestID(s.withRecovery(withSecurityHeaders(s.withAccessLog(root))))
}
