package web

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/auth"
	"platypus/internal/db"
	"platypus/internal/problem"
	"platypus/internal/session"
)

// maxBodyBytes caps request bodies. The largest legitimate body is a 64 KB
// secret value plus form overhead.
const maxBodyBytes = 1 << 20

type requestIDKey struct{}

// incomingRequestID matches request ids the gateway may set (Envoy sets
// X-Request-Id); anything else is replaced, so logs can't be polluted.
var incomingRequestID = regexp.MustCompile(`^[a-zA-Z0-9-]{8,64}$`)

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !incomingRequestID.MatchString(id) {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRecovery turns a panic into a logged error and a generic error page.
// Go stack traces show function arguments as raw machine words (pointers and
// lengths), never the text a value holds.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(recovered)
				}
				s.log.Error("panic while handling a request",
					zap.String("request_id", requestID(r.Context())),
					zap.String("path", r.URL.Path),
					zap.ByteString("stack", debug.Stack()))
				s.renderInternalError(w, r)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// contentSecurityPolicy allows only our own scripts and styles: no inline
// code, no eval, no other origins. Images may be data: URIs for QR codes.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// No referrer to other sites. Same-origin requests keep it, so a form
		// post carries its real Origin (no-referrer makes that "null"), which
		// the cross-site check needs when a browser sends no Sec-Fetch-Site.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "+
			"publickey-credentials-create=(self), publickey-credentials-get=(self)")
		// Pages show names and sometimes values: never cache them.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// cacheStatic lets browsers cache the static files for a day. In test mode
// (local development) it asks for revalidation instead, so an edited
// stylesheet shows up on a normal reload rather than a day later.
func cacheStatic(next http.Handler, cache bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cache {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// withAccessLog logs every request: method, path, status and duration. It
// never logs query strings, bodies or form fields.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if strings.HasPrefix(r.URL.Path, "/static/") {
			return
		}
		s.log.Info("request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", recorder.status),
			zap.Duration("duration", time.Since(start)),
			zap.String("request_id", requestID(r.Context())))
	})
}

// errLoginNeeded means the request has no login yet (oidc mode).
var errLoginNeeded = errors.New("login needed")

// withIdentity finds out who sends the request, in the configured way, and
// refuses requests without a valid identity.
func (s *Server) withIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(audit.WithRequest(r.Context(), requestDetails(r)))

		user, sess, err := s.identify(r)
		switch {
		case errors.Is(err, errLoginNeeded):
			s.redirectToLogin(w, r)
			return
		case errors.Is(err, auth.ErrNotAuthenticated):
			s.log.Debug("request without a valid identity", zap.String("request_id", requestID(r.Context())), zap.Error(err))
			s.services.Audit.RecordBestEffort(r.Context(), audit.Event{Action: audit.ActionAuthRejected, Outcome: audit.Denied,
				Reason: "missing or invalid identity"})
			s.renderStatus(w, r, http.StatusUnauthorized, statusNotAuthenticated)
			return
		case err != nil:
			s.fail(w, r, err)
			return
		}

		ctx := audit.WithActor(r.Context(), audit.Actor{UserID: user.ID, Email: user.Email})
		r = r.WithContext(ctx)
		if status, ok := blockedUserStatus(user); ok {
			s.renderStatus(w, r, http.StatusForbidden, status)
			return
		}

		viewer := &Viewer{User: user, Session: sess, now: s.now()}
		next.ServeHTTP(w, r.WithContext(withViewer(ctx, viewer)))
	})
}

// identify returns the user behind the request. In oidc mode that is the
// owner of the request's session; in the proxy modes the login proxy says who
// it is on every request.
func (s *Server) identify(r *http.Request) (db.User, session.Session, error) {
	if s.services.Login != nil {
		sess, found, err := s.services.Sessions.Find(r.Context(), r)
		if err != nil || !found {
			return db.User{}, session.Session{}, cmp.Or(err, errLoginNeeded)
		}
		user, err := s.services.Access.User(r.Context(), sess.UserID)
		return user, sess, err
	}

	identity, err := s.services.Auth.Verify(r)
	if err != nil {
		return db.User{}, session.Session{}, err
	}
	email, err := access.ParseEmail(identity.Email, s.settings.AllowedEmailDomains)
	if err != nil {
		return db.User{}, session.Session{}, fmt.Errorf("%w: %w", auth.ErrNotAuthenticated, err)
	}
	user, err := s.services.Access.UserForLogin(r.Context(), email, identity.Name, identity.Groups)
	return user, session.Session{}, err
}

// blockedUserStatus returns the page for users who may not use platypus.
func blockedUserStatus(user db.User) (string, bool) {
	switch {
	case user.DisabledAt != nil:
		return statusDisabled, true
	case user.LockedAt != nil:
		return statusLocked, true
	}
	return "", false
}

// redirectToLogin sends the browser to the login, to come back to the page it
// was on (oidc mode).
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.RequestURI()
	if isHTMX(r) {
		// For htmx requests, come back to the page, not to the fragment.
		if current, err := url.Parse(r.Header.Get("HX-Current-URL")); err == nil {
			returnTo = current.RequestURI()
		}
	} else if r.Method != http.MethodGet {
		returnTo = "/"
	}
	s.redirect(w, r, "/auth/login?return="+url.QueryEscape(auth.SafeReturnPath(returnTo)))
}

func requestDetails(r *http.Request) audit.Request {
	return audit.Request{
		ClientIP:  clientIP(r),
		UserAgent: truncate(r.UserAgent(), 300),
		RequestID: requestID(r.Context()),
	}
}

func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viewer := viewerFrom(r.Context())
		if !viewer.Session.Valid() {
			sess, err := s.services.Sessions.Load(r.Context(), w, r, viewer.User.ID)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			viewer.Session = sess
		}
		next.ServeHTTP(w, r)
	})
}

var crossOrigin = http.NewCrossOriginProtection()

// withCSRF refuses state-changing requests from other sites: the browser's
// own cross-origin signals must agree, and the request must carry the
// session's CSRF token (header for htmx and fetch, form field otherwise).
func (s *Server) withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if err := crossOrigin.Check(r); err != nil {
			s.fail(w, r, problem.Forbidden("This request came from another site and was refused."))
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.PostFormValue("csrf_token")
		}
		expected := viewerFrom(r.Context()).Session.CSRFToken
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			s.fail(w, r, problem.Forbidden("Your session changed. Reload the page and try again."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bootstrapPaths stay reachable while platypus is not bootstrapped: the
// bootstrap pages and the second-factor setup they use.
var bootstrapPaths = []string{"/bootstrap", "/me/security"}

// withAppState applies the application-wide switches: bootstrap mode and the
// block switch. It also loads the viewer's permissions.
func (s *Server) withAppState(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viewer := viewerFrom(r.Context())
		state, err := s.services.AppState.Get(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		viewer.State = state

		inBootstrapArea := hasAnyPrefix(r.URL.Path, bootstrapPaths)
		switch {
		case !state.Bootstrapped && !inBootstrapArea:
			s.redirect(w, r, "/bootstrap")
			return
		case state.Bootstrapped && strings.HasPrefix(r.URL.Path, "/bootstrap"):
			s.redirect(w, r, "/")
			return
		case state.Blocked && !viewer.User.IsAdmin:
			s.renderStatus(w, r, http.StatusServiceUnavailable, statusBlocked)
			return
		}

		viewer.Subject, err = s.services.Access.Subject(r.Context(), viewer.User.ID, state.Blocked)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminOnly guards admin pages: the viewer must be in the admin group and
// have confirmed admin mode with a second factor.
func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viewer := viewerFrom(r.Context())
		if viewer.InAdminMode() {
			next.ServeHTTP(w, r)
			return
		}
		if viewer.User.IsAdmin {
			if r.Method == http.MethodGet {
				s.redirect(w, r, "/admin/elevate")
				return
			}
			s.fail(w, r, problem.Forbidden("Admin mode has ended. Confirm admin mode again and retry."))
			return
		}
		s.services.Audit.RecordBestEffort(r.Context(), audit.Event{Action: audit.ActionAccessDenied, Outcome: audit.Denied,
			Name: r.URL.Path, Reason: "not an admin"})
		s.fail(w, r, problem.Forbidden("Only admins can open this page."))
	})
}

// clientIP returns where the request came from as reported by the proxies in
// front of platypus, for the audit trail.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return truncate(forwarded, 200)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
