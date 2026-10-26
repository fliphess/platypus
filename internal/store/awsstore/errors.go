package awsstore

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/smithy-go"

	"platypus/internal/sensitive"
	"platypus/internal/store"
)

// AWS error codes, grouped by how platypus handles them.
var (
	notFoundCodes = map[string]bool{
		"ParameterNotFound":         true,
		"ParameterVersionNotFound":  true,
		"ResourceNotFoundException": true,
	}
	alreadyExistsCodes = map[string]bool{
		"ParameterAlreadyExists":  true,
		"ResourceExistsException": true,
	}
	accessDeniedCodes = map[string]bool{
		"AccessDeniedException": true,
		"AccessDenied":          true,
		"DecryptionFailure":     true,
		"KMSAccessDenied":       true,
	}
	// Codes for changes a user can fix; their message is shown to the user.
	rejectedCodes = map[string]bool{
		"ValidationException":                  true,
		"InvalidRequestException":              true,
		"InvalidParameterException":            true,
		"HierarchyLevelLimitExceededException": true,
		"HierarchyTypeMismatchException":       true,
		"ParameterMaxVersionLimitExceeded":     true,
		"ParameterPatternMismatchException":    true,
		"ParameterLimitExceeded":               true,
		"UnsupportedParameterType":             true,
		"InvalidKeyId":                         true,
		"LimitExceededException":               true,
		"TooManyTagsError":                     true,
		"IncompatiblePolicyException":          true,
	}
)

// echoedValue matches the way AWS validation messages quote input back:
// "Value 'xyz' at 'value' failed to satisfy constraint".
var echoedValue = regexp.MustCompile(`(?s)Value '.*?' at '`)

// translate turns an AWS error into a store error whose text is safe to log
// and show: values passed in are scrubbed from it, and messages of unknown
// errors are dropped entirely, keeping only the operation and error code.
func translate(op string, err error, values ...sensitive.Value) error {
	if err == nil {
		return nil
	}

	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		// Transport failures (timeouts, DNS); their text holds no request data.
		return fmt.Errorf("%s: %s", op, scrub(err.Error(), values))
	}

	code := apiErr.ErrorCode()
	switch {
	case notFoundCodes[code]:
		return store.ErrNotFound
	case alreadyExistsCodes[code]:
		return store.ErrAlreadyExists
	case accessDeniedCodes[code]:
		return store.ErrAccessDenied
	case rejectedCodes[code]:
		return &store.RejectedError{Code: code, Message: scrub(apiErr.ErrorMessage(), values)}
	default:
		return fmt.Errorf("%s: AWS error %s", op, code)
	}
}

func scrub(text string, values []sensitive.Value) string {
	for _, v := range values {
		if !v.IsEmpty() {
			text = strings.ReplaceAll(text, v.Reveal(), sensitive.Redacted)
		}
	}
	return echoedValue.ReplaceAllString(text, "Value "+sensitive.Redacted+" at '")
}
