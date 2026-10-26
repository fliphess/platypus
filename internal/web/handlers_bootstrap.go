package web

import (
	"net/http"

	"platypus/internal/mfa"
)

// The bootstrap pages walk the first admin through four steps: enter the
// token from SSM, set up a second factor, save recovery codes, finish.

type bootstrapData struct {
	Step       int
	TokenParam string
	Factors    mfa.Factors
	Passkeys   bool
}

func (s *Server) bootstrapPage(w http.ResponseWriter, r *http.Request) error {
	bootstrapping, err := s.isBootstrapping(r)
	if err != nil {
		return err
	}
	data := bootstrapData{Step: 1, TokenParam: s.settings.BootstrapTokenParam, Passkeys: s.settings.PasskeysEnabled}
	if bootstrapping {
		data.Factors, err = s.services.MFA.Factors(r.Context(), viewerFrom(r.Context()).User.ID)
		if err != nil {
			return err
		}
		switch {
		case !data.Factors.Any():
			data.Step = 2
		case data.Factors.RecoveryCodesLeft == 0:
			data.Step = 3
		default:
			data.Step = 4
		}
	}
	s.render(w, r, http.StatusOK, "bootstrap", page{Title: "Set up platypus", Data: data})
	return nil
}

func (s *Server) enterBootstrapToken(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	tokenID, err := s.services.Bootstrap.VerifyToken(r.Context(), viewer.User, r.PostFormValue("token"))
	if err != nil {
		return err
	}
	if err := s.services.Sessions.SetBootstrapToken(r.Context(), viewer.Session, &tokenID); err != nil {
		return err
	}
	s.redirect(w, r, "/bootstrap")
	return nil
}

func (s *Server) completeBootstrap(w http.ResponseWriter, r *http.Request) error {
	viewer := viewerFrom(r.Context())
	bootstrapping, err := s.isBootstrapping(r)
	if err != nil {
		return err
	}
	if !bootstrapping {
		s.redirect(w, r, "/bootstrap")
		return nil
	}
	if err := s.services.Bootstrap.Complete(r.Context(), viewer.User, *viewer.Session.BootstrapTokenID); err != nil {
		return err
	}
	if err := s.services.Sessions.SetBootstrapToken(r.Context(), viewer.Session, nil); err != nil {
		return err
	}
	// Confirm admin mode once right away: it proves the new factor works.
	s.redirect(w, r, "/admin/elevate")
	return nil
}
