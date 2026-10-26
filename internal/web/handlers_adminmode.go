package web

import (
	"encoding/json"
	"net/http"

	"platypus/internal/audit"
	"platypus/internal/mfa"
	"platypus/internal/problem"
)

// Admin mode: admins use platypus as regular users, and confirm with a
// second factor to open the admin pages for a limited time.

type elevateData struct {
	Factors  mfa.Factors
	Passkeys bool
}

func (s *Server) elevatePage(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	if !viewer.User.IsAdmin {
		return problem.Forbidden("Only admins can use admin mode.")
	}
	if viewer.InAdminMode() {
		s.redirect(w, r, "/admin")
		return nil
	}
	factors, err := s.services.MFA.Factors(r.Context(), viewer.User.ID)
	if err != nil {
		return err
	}
	s.render(w, r, http.StatusOK, "elevate", page{Title: "Admin mode",
		Data: elevateData{Factors: factors, Passkeys: s.settings.PasskeysEnabled}})
	return nil
}

func (s *Server) elevateWithTOTP(w http.ResponseWriter, r *http.Request) error {
	return s.elevate(w, r, func(userID int64) error {
		return s.services.MFA.VerifyTOTP(r.Context(), userID, r.PostFormValue("code"))
	})
}

func (s *Server) elevateWithRecoveryCode(w http.ResponseWriter, r *http.Request) error {
	return s.elevate(w, r, func(userID int64) error {
		return s.services.MFA.VerifyRecoveryCode(r.Context(), userID, r.PostFormValue("code"))
	})
}

// elevate starts admin mode once verify accepts the viewer's second factor.
func (s *Server) elevate(w http.ResponseWriter, r *http.Request, verify func(userID int64) error) error {
	viewer := viewerFrom(r.Context())
	if !viewer.User.IsAdmin {
		return problem.Forbidden("Only admins can use admin mode.")
	}
	if err := verify(viewer.User.ID); err != nil {
		return err
	}
	if err := s.startAdminMode(r, viewer); err != nil {
		return err
	}
	s.redirect(w, r, "/admin?notice=admin-on")
	return nil
}

func (s *Server) startAdminMode(r *http.Request, viewer *Viewer) error {
	until := s.now().Add(s.settings.AdminModeDuration)
	if err := s.services.Sessions.SetAdminMode(r.Context(), viewer.Session, &until); err != nil {
		return err
	}
	return s.services.Audit.Record(r.Context(), audit.Event{Action: audit.ActionAdminModeEnter, Outcome: audit.Allowed,
		Details: map[string]any{"until": until}})
}

func (s *Server) beginPasskeyElevation(w http.ResponseWriter, r *http.Request) error {
	if !s.settings.PasskeysEnabled {
		return errPasskeysOff
	}
	viewer := viewerFrom(r.Context())
	if !viewer.User.IsAdmin {
		return problem.Forbidden("Only admins can use admin mode.")
	}
	options, state, err := s.services.MFA.BeginPasskeyLogin(r.Context(), viewer.User)
	if err != nil {
		return err
	}
	if err := s.services.Sessions.SaveCeremony(r.Context(), viewer.Session, state); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, json.RawMessage(options))
}

func (s *Server) finishPasskeyElevation(w http.ResponseWriter, r *http.Request) error {
	if !s.settings.PasskeysEnabled {
		return errPasskeysOff
	}
	viewer := viewerFrom(r.Context())
	if !viewer.User.IsAdmin {
		return problem.Forbidden("Only admins can use admin mode.")
	}
	var body struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	state, ok, err := s.services.Sessions.TakeCeremony(r.Context(), viewer.Session)
	if err != nil {
		return err
	}
	if !ok {
		return problem.Invalid("Start the passkey step again.")
	}
	if err := s.services.MFA.FinishPasskeyLogin(r.Context(), viewer.User, state, body.Credential); err != nil {
		return err
	}
	if err := s.startAdminMode(r, viewer); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]string{"redirect": "/admin?notice=admin-on"})
}

func (s *Server) leaveAdminMode(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	if err := s.services.Sessions.SetAdminMode(r.Context(), viewer.Session, nil); err != nil {
		return err
	}
	if err := s.services.Audit.Record(r.Context(), audit.Event{Action: audit.ActionAdminModeLeave, Outcome: audit.Allowed}); err != nil {
		return err
	}
	s.redirect(w, r, "/?notice=admin-off")
	return nil
}
