package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"platypus/internal/audit"
	"platypus/internal/database"
	"platypus/internal/db"
	"platypus/internal/problem"
	"platypus/internal/textclean"
)

// A passkey step takes two requests: Begin returns options for the browser
// and a ceremony the caller keeps in the session; Finish checks the browser's
// answer against that ceremony.

type ceremonyPurpose string

const (
	purposeRegister ceremonyPurpose = "register"
	purposeLogin    ceremonyPurpose = "login"
)

type ceremony struct {
	Purpose ceremonyPurpose      `json:"purpose"`
	Session webauthn.SessionData `json:"session"`
}

// webauthnUser adapts a platypus user to the WebAuthn library.
type webauthnUser struct {
	user        db.User
	credentials []webauthn.Credential
}

func (u webauthnUser) WebAuthnID() []byte                         { return u.user.WebAuthnHandle }
func (u webauthnUser) WebAuthnName() string                       { return u.user.Email }
func (u webauthnUser) WebAuthnDisplayName() string                { return u.user.Email }
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Service) loadWebAuthnUser(ctx context.Context, user db.User) (webauthnUser, []db.Passkey, error) {
	passkeys, err := s.queries.ListPasskeys(ctx, user.ID)
	if err != nil {
		return webauthnUser{}, nil, fmt.Errorf("load passkeys: %w", err)
	}
	wu := webauthnUser{user: user}
	for _, pk := range passkeys {
		var cred webauthn.Credential
		if err := json.Unmarshal(pk.Credential, &cred); err != nil {
			return webauthnUser{}, nil, fmt.Errorf("decode passkey %d: %w", pk.ID, err)
		}
		wu.credentials = append(wu.credentials, cred)
	}
	return wu, passkeys, nil
}

// passkeys returns the WebAuthn setup, or an error when passkeys are off.
func (s *Service) passkeys() (*webauthn.WebAuthn, error) {
	if s.webauthn == nil {
		return nil, problem.NotFound("Passkeys are switched off here; use an authenticator app.")
	}
	return s.webauthn, nil
}

// BeginPasskeyRegistration starts adding a passkey. It returns the options
// for navigator.credentials.create() and the ceremony to keep.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, user db.User) (options, state []byte, err error) {
	wa, err := s.passkeys()
	if err != nil {
		return nil, nil, err
	}
	wu, _, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	exclude := make([]protocol.CredentialDescriptor, len(wu.credentials))
	for i, cred := range wu.credentials {
		exclude[i] = cred.Descriptor()
	}
	creation, session, err := wa.BeginRegistration(wu,
		webauthn.WithExclusions(exclude),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("begin passkey registration: %w", err)
	}
	return marshalCeremony(creation, purposeRegister, session)
}

// FinishPasskeyRegistration checks the browser's answer and stores the passkey.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, user db.User, state, response []byte, name string) error {
	wa, err := s.passkeys()
	if err != nil {
		return err
	}
	session, err := unmarshalCeremony(state, purposeRegister)
	if err != nil {
		return err
	}
	name, err = textclean.Clean(name, textclean.Options{MaxLength: 60})
	if err != nil {
		return problem.Invalid("Passkey name: %v.", err)
	}
	if name == "" {
		name = "Passkey"
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return problem.Invalid("The browser's passkey answer could not be read; please try again.")
	}
	wu, _, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return err
	}
	cred, err := wa.CreateCredential(wu, session, parsed)
	if err != nil {
		return problem.Invalid("The passkey could not be verified; please try again.")
	}

	stored, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("encode passkey: %w", err)
	}
	err = s.queries.CreatePasskey(ctx, db.CreatePasskeyParams{
		UserID: user.ID, CredentialID: cred.ID, Credential: stored, Name: name,
	})
	if database.IsUniqueViolation(err) {
		return problem.Conflict("This passkey is registered already.")
	}
	if err != nil {
		return fmt.Errorf("store passkey: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionPasskeyAdded, Outcome: audit.Allowed,
		Details: map[string]any{"name": name}})
	return nil
}

// BeginPasskeyLogin starts confirming admin mode with a passkey.
func (s *Service) BeginPasskeyLogin(ctx context.Context, user db.User) (options, state []byte, err error) {
	wa, err := s.passkeys()
	if err != nil {
		return nil, nil, err
	}
	wu, _, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	if len(wu.credentials) == 0 {
		return nil, nil, problem.Invalid("You have no passkeys.")
	}
	assertion, session, err := wa.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, fmt.Errorf("begin passkey login: %w", err)
	}
	return marshalCeremony(assertion, purposeLogin, session)
}

// FinishPasskeyLogin checks the browser's answer. Failures count towards the
// lockout.
func (s *Service) FinishPasskeyLogin(ctx context.Context, user db.User, state, response []byte) error {
	wa, err := s.passkeys()
	if err != nil {
		return err
	}
	session, err := unmarshalCeremony(state, purposeLogin)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return s.guard.Failed(ctx, user.ID, "passkey")
	}
	wu, passkeys, err := s.loadWebAuthnUser(ctx, user)
	if err != nil {
		return err
	}
	cred, err := wa.ValidateLogin(wu, session, parsed)
	if err != nil {
		return s.guard.Failed(ctx, user.ID, "passkey")
	}
	if cred.Authenticator.CloneWarning {
		// The signature counter went backwards: the passkey may be copied.
		return s.guard.Failed(ctx, user.ID, "passkey (possibly cloned)")
	}

	for _, pk := range passkeys {
		if bytes.Equal(pk.CredentialID, cred.ID) {
			stored, err := json.Marshal(cred)
			if err != nil {
				return fmt.Errorf("encode passkey: %w", err)
			}
			if err := s.queries.UpdatePasskeyAfterLogin(ctx, db.UpdatePasskeyAfterLoginParams{ID: pk.ID, Credential: stored}); err != nil {
				return fmt.Errorf("update passkey: %w", err)
			}
		}
	}
	return s.guard.Succeeded(ctx, user.ID)
}

// RemovePasskey deletes one of the user's passkeys.
func (s *Service) RemovePasskey(ctx context.Context, userID, passkeyID int64) error {
	if err := s.queries.DeletePasskey(ctx, db.DeletePasskeyParams{ID: passkeyID, UserID: userID}); err != nil {
		return fmt.Errorf("remove passkey: %w", err)
	}
	s.audit.RecordBestEffort(ctx, audit.Event{Action: audit.ActionPasskeyRemoved, Outcome: audit.Allowed,
		Details: map[string]any{"passkey_id": passkeyID}})
	return nil
}

func marshalCeremony(options any, purpose ceremonyPurpose, session *webauthn.SessionData) ([]byte, []byte, error) {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, nil, fmt.Errorf("encode passkey options: %w", err)
	}
	state, err := json.Marshal(ceremony{Purpose: purpose, Session: *session})
	if err != nil {
		return nil, nil, fmt.Errorf("encode passkey ceremony: %w", err)
	}
	return optionsJSON, state, nil
}

var errNoCeremony = problem.Invalid("The passkey step expired; please start again.")

func unmarshalCeremony(state []byte, purpose ceremonyPurpose) (webauthn.SessionData, error) {
	if len(state) == 0 {
		return webauthn.SessionData{}, errNoCeremony
	}
	var c ceremony
	if err := json.Unmarshal(state, &c); err != nil {
		return webauthn.SessionData{}, errors.Join(errNoCeremony, err)
	}
	if c.Purpose != purpose {
		return webauthn.SessionData{}, errNoCeremony
	}
	return c.Session, nil
}
