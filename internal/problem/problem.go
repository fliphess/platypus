// Package problem describes errors the user can understand: invalid input,
// missing permissions, things that don't exist or changed meanwhile. Their
// message is shown on screen as is. Any other error is an internal failure
// and the user only sees a generic message.
package problem

import (
	"errors"
	"fmt"
)

// Kind classifies a problem; the web layer maps it to an HTTP status.
type Kind int

const (
	KindInvalid Kind = iota + 1
	KindForbidden
	KindNotFound
	KindConflict
	KindTooManyRequests
)

// Problem is an error with a message meant for the user.
type Problem struct {
	Kind    Kind
	Message string
}

func (p *Problem) Error() string { return p.Message }

func newProblem(kind Kind, format string, args []any) *Problem {
	return &Problem{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Invalid reports input the user has to correct.
func Invalid(format string, args ...any) error { return newProblem(KindInvalid, format, args) }

// Forbidden reports a missing permission.
func Forbidden(format string, args ...any) error { return newProblem(KindForbidden, format, args) }

// NotFound reports something that doesn't exist, or that the user may not know about.
func NotFound(format string, args ...any) error { return newProblem(KindNotFound, format, args) }

// Conflict reports a change that clashes with the current state.
func Conflict(format string, args ...any) error { return newProblem(KindConflict, format, args) }

// TooManyRequests reports a rate limit.
func TooManyRequests(format string, args ...any) error {
	return newProblem(KindTooManyRequests, format, args)
}

// As returns the Problem in err's chain, if any.
func As(err error) (*Problem, bool) {
	var p *Problem
	ok := errors.As(err, &p)
	return p, ok
}
