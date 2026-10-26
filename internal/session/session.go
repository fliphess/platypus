// Package session keeps a small server-side session per browser: the CSRF
// token, admin mode and in-progress bootstrap or passkey steps.
//
// In the proxy modes, who the user is comes from the proxy on every request;
// a session belongs to one user, and a different user gets a fresh session.
// In oidc mode the session is the login itself: when it ends, the user logs
// in again.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"platypus/internal/database"
	"platypus/internal/db"
)

// Session is the server-side state of one browser session.
type Session struct {
	idHash           []byte
	UserID           int64
	CSRFToken        string
	AdminModeUntil   *time.Time
	BootstrapTokenID *int64
	ceremony         []byte
	ceremonyUntil    *time.Time
}

// Valid reports whether the Session was loaded or started (not the zero value).
func (s Session) Valid() bool {
	return s.idHash != nil
}

// InAdminMode reports whether admin mode is active at now.
func (s Session) InAdminMode(now time.Time) bool {
	return s.AdminModeUntil != nil && now.Before(*s.AdminModeUntil)
}

// Ceremony returns the stored passkey ceremony, if it hasn't expired.
func (s Session) Ceremony(now time.Time) ([]byte, bool) {
	if s.ceremony == nil || s.ceremonyUntil == nil || !now.Before(*s.ceremonyUntil) {
		return nil, false
	}
	return s.ceremony, true
}

// Manager loads and stores sessions.
type Manager struct {
	queries     *db.Queries
	idleTimeout time.Duration
	maxAge      time.Duration
	cookieName  string
	secure      bool
	now         func() time.Time
}

// NewManager returns a Manager. secure sets the Secure flag on the cookie
// (and the __Host- name prefix, which requires it); only test mode on plain
// http runs without.
func NewManager(queries *db.Queries, idleTimeout, maxAge time.Duration, secure bool) *Manager {
	name := "platypus_session"
	if secure {
		name = "__Host-platypus_session"
	}
	return &Manager{
		queries:     queries,
		idleTimeout: idleTimeout,
		maxAge:      maxAge,
		cookieName:  name,
		secure:      secure,
		now:         time.Now,
	}
}

// touchInterval limits how often an active session's expiry is extended.
const touchInterval = time.Minute

// Find returns the live session of the request, if it has one, and extends
// it. It never starts a session.
func (m *Manager) Find(ctx context.Context, r *http.Request) (Session, bool, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return Session{}, false, nil
	}
	row, err := m.queries.GetSession(ctx, hashID(cookie.Value))
	if database.IsNoRows(err) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("load session: %w", err)
	}
	if err := m.touch(ctx, row); err != nil {
		return Session{}, false, err
	}
	return fromRow(row), true, nil
}

// Load returns the session of the request for userID, starting a new one
// (and setting its cookie) when there is none, it expired, or it belongs to
// someone else. The proxy modes use it on every request.
func (m *Manager) Load(ctx context.Context, w http.ResponseWriter, r *http.Request, userID int64) (Session, error) {
	sess, found, err := m.Find(ctx, r)
	switch {
	case err != nil:
		return Session{}, err
	case found && sess.UserID == userID:
		return sess, nil
	case found:
		// The identity changed under this cookie: drop the old session.
		if err := m.queries.DeleteSession(ctx, sess.idHash); err != nil {
			return Session{}, fmt.Errorf("delete session: %w", err)
		}
	}
	return m.Start(ctx, w, userID)
}

// Start begins a new session for userID and sets its cookie. Starting a fresh
// session at login (rather than reusing one) rules out session fixation.
func (m *Manager) Start(ctx context.Context, w http.ResponseWriter, userID int64) (Session, error) {
	id, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	now := m.now()
	err = m.queries.CreateSession(ctx, db.CreateSessionParams{
		IDHash:    hashID(id),
		UserID:    userID,
		CSRFToken: csrf,
		ExpiresAt: now.Add(min(m.idleTimeout, m.maxAge)),
	})
	if err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	// Secure is only false in test mode on plain http; see NewManager.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see above
		Name:     m.cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	})
	return Session{idHash: hashID(id), UserID: userID, CSRFToken: csrf}, nil
}

// touch extends an active session, never beyond its maximum age.
func (m *Manager) touch(ctx context.Context, row db.Session) error {
	now := m.now()
	if now.Sub(row.LastSeenAt) < touchInterval {
		return nil
	}
	expires := now.Add(m.idleTimeout)
	if hardLimit := row.CreatedAt.Add(m.maxAge); hardLimit.Before(expires) {
		expires = hardLimit
	}
	if err := m.queries.TouchSession(ctx, db.TouchSessionParams{IDHash: row.IDHash, ExpiresAt: expires}); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// SetAdminMode starts admin mode until the given time, or ends it with nil.
func (m *Manager) SetAdminMode(ctx context.Context, s Session, until *time.Time) error {
	return m.queries.SetAdminMode(ctx, db.SetAdminModeParams{IDHash: s.idHash, AdminModeUntil: until})
}

// SetBootstrapToken remembers (or forgets, with nil) a verified bootstrap token.
func (m *Manager) SetBootstrapToken(ctx context.Context, s Session, tokenID *int64) error {
	return m.queries.SetSessionBootstrapToken(ctx, db.SetSessionBootstrapTokenParams{IDHash: s.idHash, BootstrapTokenID: tokenID})
}

// ceremonyLifetime is how long a user has to finish a passkey step.
const ceremonyLifetime = 5 * time.Minute

// SaveCeremony stores the state of a passkey step that is in progress.
func (m *Manager) SaveCeremony(ctx context.Context, s Session, ceremony []byte) error {
	return m.queries.SetWebAuthnCeremony(ctx, db.SetWebAuthnCeremonyParams{
		IDHash:        s.idHash,
		Ceremony:      ceremony,
		CeremonyUntil: new(m.now().Add(ceremonyLifetime)),
	})
}

// ClearCeremony forgets a passkey step, so it can't be finished twice.
func (m *Manager) ClearCeremony(ctx context.Context, s Session) error {
	return m.queries.ClearWebAuthnCeremony(ctx, s.idHash)
}

// End ends a session and removes its cookie.
func (m *Manager) End(ctx context.Context, w http.ResponseWriter, s Session) error {
	http.SetCookie(w, &http.Cookie{Name: m.cookieName, Value: "", Path: "/", MaxAge: -1, //nolint:gosec // removes the cookie
		HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteStrictMode})
	if !s.Valid() {
		return nil
	}
	return m.queries.DeleteSession(ctx, s.idHash)
}

// EndUserSessions ends every session of a user.
func (m *Manager) EndUserSessions(ctx context.Context, userID int64) error {
	return m.queries.DeleteUserSessions(ctx, userID)
}

// Cleanup removes expired sessions.
func (m *Manager) Cleanup(ctx context.Context) error {
	return m.queries.DeleteExpiredSessions(ctx)
}

func fromRow(row db.Session) Session {
	return Session{
		idHash:           row.IDHash,
		UserID:           row.UserID,
		CSRFToken:        row.CSRFToken,
		AdminModeUntil:   row.AdminModeUntil,
		BootstrapTokenID: row.BootstrapTokenID,
		ceremony:         row.WebAuthnCeremony,
		ceremonyUntil:    row.WebAuthnCeremonyUntil,
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashID is what the database stores instead of the cookie value, so a copy
// of the database can't be used to take over sessions.
func hashID(id string) []byte {
	sum := sha256.Sum256([]byte(id))
	return sum[:]
}
