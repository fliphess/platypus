// Package store talks to AWS: SSM Parameter Store and Secrets Manager.
//
// The interfaces here are all platypus needs from AWS. Package awsstore
// implements them with the AWS SDK; package memstore implements them in
// memory for tests. Values only ever travel as sensitive.Value.
//
// Nothing in this package checks permissions: callers do that first.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"platypus/internal/sensitive"
)

var (
	// ErrNotFound means the item (or version) doesn't exist.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists means an item with that name exists already.
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict means the item changed since the caller last saw it.
	ErrConflict = errors.New("changed by someone else")
	// ErrAccessDenied means AWS denied platypus itself access to the item.
	ErrAccessDenied = errors.New("platypus has no access")
	// ErrBinaryValue means a secret holds binary data, which platypus doesn't support.
	ErrBinaryValue = errors.New("binary secret values are not supported")
)

// RejectedError means AWS refused a change for a reason the user can fix, such
// as an invalid value for the parameter type. Message comes from AWS and never
// contains the value.
type RejectedError struct {
	Code    string
	Message string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("AWS refused the change (%s): %s", e.Code, e.Message)
}

// Parameter is the metadata of an SSM parameter.
type Parameter struct {
	Name           string
	Type           string
	Tier           string
	DataType       string
	Description    string
	KMSKeyID       string
	Version        int64
	LastModified   time.Time
	LastModifiedBy string
}

// ParameterVersion is one entry in a parameter's history.
type ParameterVersion struct {
	Version        int64
	Type           string
	Tier           string
	Description    string
	Labels         []string
	LastModified   time.Time
	LastModifiedBy string
}

// NewParameter is a parameter to create.
type NewParameter struct {
	Name        string
	Value       sensitive.Value
	Type        string
	Tier        string
	Description string
	Tags        map[string]string
}

// ParameterUpdate replaces a parameter's value and settings, creating a new
// version. SSM can't change a description without writing the value, so the
// value is always part of an update.
type ParameterUpdate struct {
	Name        string
	Value       sensitive.Value
	Type        string
	Tier        string
	Description string
	// ExpectVersion is the version the user started editing; the update fails
	// with ErrConflict if the parameter has moved on since.
	ExpectVersion int64
}

// Parameters is SSM Parameter Store.
type Parameters interface {
	// List calls fn for every parameter.
	List(ctx context.Context, fn func(Parameter) error) error
	// Describe returns the metadata of one parameter.
	Describe(ctx context.Context, name string) (Parameter, error)
	// Tags returns the tags of a parameter.
	Tags(ctx context.Context, name string) (map[string]string, error)
	// Value returns the decrypted value of a version; version 0 means current.
	Value(ctx context.Context, name string, version int64) (sensitive.Value, error)
	// History returns all versions, newest first, without values.
	History(ctx context.Context, name string) ([]ParameterVersion, error)
	// Create creates a parameter. It never overwrites: an existing name
	// returns ErrAlreadyExists.
	Create(ctx context.Context, p NewParameter) (Parameter, error)
	// Update writes a new version of an existing parameter.
	Update(ctx context.Context, u ParameterUpdate) (Parameter, error)
	// CheckAccess returns nil if platypus can read the parameter,
	// ErrAccessDenied if AWS denies it, or ErrNotFound.
	CheckAccess(ctx context.Context, name string) error
}

// TokenWriter writes platypus's own bootstrap token. It is separate from
// Parameters on purpose: an overwrite without any checks must not be within
// reach of the code that handles users' parameters.
type TokenWriter interface {
	// Write creates or overwrites a SecureString without any checks.
	Write(ctx context.Context, name string, value sensitive.Value, description string) error
}

// Secret is the metadata of a Secrets Manager secret.
type Secret struct {
	Name             string
	ARN              string
	Description      string
	KMSKeyID         string
	CurrentVersionID string
	LastChanged      time.Time
	RotationEnabled  bool
	// DeletedDate is set while the secret is scheduled for deletion; it can
	// be read nowhere until it is restored.
	DeletedDate *time.Time
	Tags        map[string]string
}

// SecretVersion is one version of a secret.
type SecretVersion struct {
	ID      string
	Stages  []string
	Created time.Time
}

// IsCurrent reports whether this is the version in use.
func (v SecretVersion) IsCurrent() bool {
	for _, stage := range v.Stages {
		if stage == StageCurrent {
			return true
		}
	}
	return false
}

// Secrets Manager version stages.
const (
	StageCurrent  = "AWSCURRENT"
	StagePrevious = "AWSPREVIOUS"
)

// NewSecret is a secret to create.
type NewSecret struct {
	Name        string
	Value       sensitive.Value
	Description string
	Tags        map[string]string
}

// Secrets is AWS Secrets Manager.
type Secrets interface {
	// List calls fn for every secret that isn't scheduled for deletion.
	List(ctx context.Context, fn func(Secret) error) error
	// Describe returns the metadata of one secret.
	Describe(ctx context.Context, name string) (Secret, error)
	// Value returns the value of a version; an empty versionID means current.
	// Binary secrets return ErrBinaryValue.
	Value(ctx context.Context, name, versionID string) (sensitive.Value, error)
	// Versions returns the versions that still have a stage, newest first.
	Versions(ctx context.Context, name string) ([]SecretVersion, error)
	// Create creates a secret. It never overwrites.
	Create(ctx context.Context, s NewSecret) (Secret, error)
	// PutValue stores a new current version. expectVersionID is the current
	// version the user started from (ErrConflict otherwise).
	PutValue(ctx context.Context, name string, value sensitive.Value, expectVersionID string) (Secret, error)
	// UpdateDescription changes the description without a new version. It
	// returns ErrConflict when the current version isn't expectVersionID.
	UpdateDescription(ctx context.Context, name, description, expectVersionID string) error
	// Restore makes an earlier version current again, without handling the
	// value at all. expectVersionID works as in PutValue.
	Restore(ctx context.Context, name, versionID, expectVersionID string) error
	// Undelete cancels a scheduled deletion.
	Undelete(ctx context.Context, name string) error
	// CheckAccess works as Parameters.CheckAccess.
	CheckAccess(ctx context.Context, name string) error
}
