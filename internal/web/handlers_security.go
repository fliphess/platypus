package web

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"

	"go.uber.org/zap"

	"platypus/internal/mfa"
	"platypus/internal/problem"
)

// Second factors guard admin mode, so only admins (and whoever is setting up
// platypus during bootstrap) manage them.

type factorAccess struct {
	Bootstrapping bool
	Factors       mfa.Factors
}

// securityAccess checks who may see or change second factors. Changing them
// when some exist needs admin mode, so a stolen login session alone can't add
// an attacker's authenticator. Recovery codes count: an admin who removed
// their last authenticator but kept recovery codes still has a factor.
func (s *Server) securityAccess(r *http.Request, change bool) (factorAccess, error) {
	viewer := viewerFrom(r.Context())
	bootstrapping, err := s.isBootstrapping(r)
	if err != nil {
		return factorAccess{}, err
	}
	if !viewer.User.IsAdmin && !bootstrapping {
		return factorAccess{}, problem.Forbidden("Only admins use second factors in platypus.")
	}
	factors, err := s.services.MFA.Factors(r.Context(), viewer.User.ID)
	if err != nil {
		return factorAccess{}, err
	}
	if change && factors.AnyIncludingRecoveryCodes() && !viewer.InAdminMode() && !bootstrapping {
		return factorAccess{}, problem.Forbidden("Confirm admin mode first: changing second factors needs one of your current ones.")
	}
	return factorAccess{Bootstrapping: bootstrapping, Factors: factors}, nil
}

// isBootstrapping reports whether the viewer entered a valid bootstrap token
// and platypus is still waiting for its first admin.
func (s *Server) isBootstrapping(r *http.Request) (bool, error) {
	viewer := viewerFrom(r.Context())
	if viewer.State.Bootstrapped || viewer.Session.BootstrapTokenID == nil {
		return false, nil
	}
	return s.services.Bootstrap.TokenStillValid(r.Context(), *viewer.Session.BootstrapTokenID)
}

// securityDone is where to go after changing a factor.
func securityDone(access factorAccess, notice string) string {
	if access.Bootstrapping {
		return "/bootstrap"
	}
	return "/me/security?notice=" + notice
}

type securityData struct {
	Factors       mfa.Factors
	Bootstrapping bool
	CanChange     bool
	Passkeys      bool
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) error {
	access, err := s.securityAccess(r, false)
	if err != nil {
		return err
	}
	viewer := viewerFrom(r.Context())
	data := securityData{
		Factors:       access.Factors,
		Bootstrapping: access.Bootstrapping,
		CanChange:     !access.Factors.AnyIncludingRecoveryCodes() || viewer.InAdminMode() || access.Bootstrapping,
		Passkeys:      s.settings.PasskeysEnabled,
	}
	s.render(w, r, http.StatusOK, "security", page{Title: "Second factors", Tab: "me", Data: data})
	return nil
}

func (s *Server) startTOTP(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.securityAccess(r, true); err != nil {
		return err
	}
	enrollment, err := s.services.MFA.StartTOTPEnrollment(r.Context(), viewerFrom(r.Context()).User)
	if err != nil {
		return err
	}
	s.renderFragment(w, r, http.StatusOK, "security", "totp-setup", totpSetupData{
		Secret: enrollment.Secret,
		// html/template refuses data: URLs from strings; this one is a PNG
		// platypus rendered itself, so it is marked safe explicitly.
		QRCode:    template.URL(enrollment.QRCode), //nolint:gosec // see above
		CSRFToken: viewerFrom(r.Context()).Session.CSRFToken,
	})
	return nil
}

type totpSetupData struct {
	Secret    string
	QRCode    template.URL
	CSRFToken string
}

func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) error {
	access, err := s.securityAccess(r, true)
	if err != nil {
		return err
	}
	if err := s.services.MFA.ConfirmTOTPEnrollment(r.Context(), viewerFrom(r.Context()).User, r.PostFormValue("code")); err != nil {
		return err
	}
	s.redirect(w, r, securityDone(access, "factor-added"))
	return nil
}

func (s *Server) removeTOTP(w http.ResponseWriter, r *http.Request) error {
	access, err := s.securityAccess(r, true)
	if err != nil {
		return err
	}
	if err := s.services.MFA.RemoveTOTP(r.Context(), viewerFrom(r.Context()).User.ID); err != nil {
		return err
	}
	s.redirect(w, r, securityDone(access, "removed"))
	return nil
}

func (s *Server) removePasskey(w http.ResponseWriter, r *http.Request) error {
	access, err := s.securityAccess(r, true)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(r.PostFormValue("passkey_id"), 10, 64)
	if err != nil {
		return problem.Invalid("Unknown passkey.")
	}
	if err := s.services.MFA.RemovePasskey(r.Context(), viewerFrom(r.Context()).User.ID, id); err != nil {
		return err
	}
	s.redirect(w, r, securityDone(access, "removed"))
	return nil
}

type recoveryCodesData struct {
	Codes    []string
	Continue string
}

// issueRecoveryCodes shows new recovery codes once. They are not stored in
// readable form, so this page is the only chance to save them.
func (s *Server) issueRecoveryCodes(w http.ResponseWriter, r *http.Request) error {
	access, err := s.securityAccess(r, true)
	if err != nil {
		return err
	}
	if !access.Factors.Any() {
		return problem.Invalid("Set up an authenticator app or a passkey first.")
	}
	codes, err := s.services.MFA.IssueRecoveryCodes(r.Context(), viewerFrom(r.Context()).User.ID)
	if err != nil {
		return err
	}
	s.render(w, r, http.StatusOK, "recovery_codes", page{Title: "Recovery codes", Tab: "me",
		Data: recoveryCodesData{Codes: codes, Continue: securityDone(access, "saved")}})
	return nil
}

// errPasskeysOff answers passkey requests where passkeys are switched off.
var errPasskeysOff = problem.NotFound("Passkeys are switched off here; use an authenticator app.")

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) error {
	if !s.settings.PasskeysEnabled {
		return errPasskeysOff
	}
	if _, err := s.securityAccess(r, true); err != nil {
		return err
	}
	viewer := viewerFrom(r.Context())
	options, state, err := s.services.MFA.BeginPasskeyRegistration(r.Context(), viewer.User)
	if err != nil {
		return err
	}
	if err := s.services.Sessions.SaveCeremony(r.Context(), viewer.Session, state); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, json.RawMessage(options))
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) error {
	if !s.settings.PasskeysEnabled {
		return errPasskeysOff
	}
	access, err := s.securityAccess(r, true)
	if err != nil {
		return err
	}
	viewer := viewerFrom(r.Context())
	var body struct {
		Name       string          `json:"name"`
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
	if err := s.services.MFA.FinishPasskeyRegistration(r.Context(), viewer.User, state, body.Credential, body.Name); err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]string{"redirect": securityDone(access, "factor-added")})
}

// handleJSON is handle for endpoints called by fetch(): errors are JSON too.
func (s *Server) handleJSON(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		if p, ok := problem.As(err); ok {
			_ = writeJSON(w, statusFor(p.Kind), map[string]string{"error": p.Message})
			return
		}
		s.log.Error("request failed", zap.String("request_id", requestID(r.Context())),
			zap.String("path", r.URL.Path), zap.Error(err))
		_ = writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Something went wrong on our side (request id " + requestID(r.Context()) + ").",
		})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return problem.Invalid("The request is too large.")
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return problem.Invalid("The request could not be read.")
	}
	return nil
}
