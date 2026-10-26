package web

import (
	"errors"
	"net/http"

	"go.uber.org/zap"

	"platypus/internal/access"
	"platypus/internal/audit"
	"platypus/internal/problem"
)

// Login, callback and logout exist in oidc mode only. In the proxy modes the
// login proxy owns the login.

var errNoLogin = problem.NotFound("Platypus doesn't handle the login itself here; your login proxy does.")

// startLogin sends the browser to the identity provider.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request) error {
	if s.services.Login == nil {
		return errNoLogin
	}
	providerURL, err := s.services.Login.StartLogin(w, r.URL.Query().Get("return"))
	if err != nil {
		return err
	}
	// The identity provider's own login URL, from its discovery document.
	http.Redirect(w, r, providerURL, http.StatusFound) //nolint:gosec // see above
	return nil
}

// finishLogin handles the identity provider sending the browser back: it
// checks the login, starts a fresh session and continues to where the user
// was going.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) error {
	if s.services.Login == nil {
		return errNoLogin
	}
	ctx := audit.WithRequest(r.Context(), requestDetails(r))
	r = r.WithContext(ctx)

	identity, returnTo, err := s.services.Login.FinishLogin(w, r)
	if err == nil {
		identity.Email, err = access.ParseEmail(identity.Email, s.settings.AllowedEmailDomains)
	}
	if err != nil {
		s.log.Warn("login failed", zap.String("request_id", requestID(ctx)), zap.Error(err))
		s.services.Audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionAuthRejected, Outcome: audit.Denied,
			Reason: "login failed", Details: map[string]any{"email": identity.Email}})
		var p *problem.Problem
		if !errors.As(err, &p) {
			err = problem.Forbidden("The login could not be completed. Please try again.")
		}
		return err
	}

	user, err := s.services.Access.UserForLogin(ctx, identity.Email, identity.Name, identity.Groups)
	if err != nil {
		return err
	}
	ctx = audit.WithActor(ctx, audit.Actor{UserID: user.ID, Email: user.Email})
	r = r.WithContext(ctx)
	if status, blocked := blockedUserStatus(user); blocked {
		s.renderStatus(w, r, http.StatusForbidden, status)
		return nil
	}

	if _, err := s.services.Sessions.Start(ctx, w, user.ID); err != nil {
		return err
	}
	s.services.Audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionLogin, Outcome: audit.Allowed})

	// The browser arrived here from the identity provider's site, so it
	// won't send the SameSite=Strict session cookie on a redirect that
	// continues this navigation. A page that moves on by itself starts a new,
	// same-site navigation, which does carry the cookie.
	s.renderFragment(w, r, http.StatusOK, "status", "continue", returnTo)
	return nil
}

// logout ends the session (oidc mode). The identity provider's own session
// is untouched; PLATYPUS_OIDC_PROMPT=login makes the next login ask again.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	if s.services.Login == nil {
		return errNoLogin
	}
	viewer := viewerFrom(r.Context())
	if err := s.services.Sessions.End(r.Context(), w, viewer.Session); err != nil {
		return err
	}
	s.services.Audit.RecordBestEffort(r.Context(), audit.Event{Action: audit.ActionLogout, Outcome: audit.Allowed})
	s.redirect(w, r, "/auth/logged-out")
	return nil
}

// loggedOut confirms the logout. It is outside the login, like the login pages.
func (s *Server) loggedOut(w http.ResponseWriter, r *http.Request) error {
	s.render(w, r, http.StatusOK, "status", page{Title: "Logged out", Data: statusContent{
		Title: "You are logged out", Message: "Close this tab, or log in again.", LoginLink: true,
	}})
	return nil
}
