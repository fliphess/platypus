// Package textclean cleans free text before platypus stores or sends it:
// notes, descriptions and names of teams and policies.
//
// Output escaping in the HTML templates is the main defence against script
// injection; cleaning on input is a second layer and keeps stored text plain.
package textclean

import (
	"errors"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/microcosm-cc/bluemonday"
)

var strict = bluemonday.StrictPolicy()

// leftoverTags matches markup that the bounded decode rounds have just
// revealed; it requires a tag-like first character so plain "a < b > c" text
// is left alone.
var leftoverTags = regexp.MustCompile(`</?[a-zA-Z][^>]*>`)

// Options control how text is cleaned.
type Options struct {
	// MaxLength is the maximum number of characters after cleaning.
	MaxLength int
	// Multiline keeps line breaks; otherwise they become spaces.
	Multiline bool
}

// Identifier validates a value used as an authorization key, such as an
// identity-provider group name. Surrounding whitespace is trimmed; nothing
// else is rewritten, because stripping markup or entities out of an
// identifier would silently merge two distinct identities.
func Identifier(text string, maxLength int) (string, error) {
	if !utf8.ValidString(text) {
		return "", errors.New("the text contains invalid characters")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil
	}
	for _, r := range text {
		if unicode.IsControl(r) || isDirectionControl(r) || r == utf8.RuneError {
			return "", errors.New("the text contains control characters")
		}
	}
	if n := utf8.RuneCountInString(text); maxLength > 0 && n > maxLength {
		return "", fmt.Errorf("the text can be at most %d characters (it is %d)", maxLength, n)
	}
	return text, nil
}

// Clean removes HTML tags (including encoded ones), control characters and
// Unicode direction overrides, normalises line breaks and trims the result.
// It returns an error when the text is too long or not valid UTF-8.
func Clean(text string, opts Options) (string, error) {
	if !utf8.ValidString(text) {
		return "", errors.New("the text contains invalid characters")
	}

	text = stripTags(text)

	var b strings.Builder
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, r := range text {
		switch {
		case r == '\n' || r == '\r':
			if opts.Multiline {
				b.WriteRune('\n')
			} else {
				b.WriteRune(' ')
			}
		case r == '\t':
			b.WriteRune(' ')
		case isDirectionControl(r), unicode.IsControl(r), r == utf8.RuneError:
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	cleaned := strings.TrimSpace(b.String())

	if n := utf8.RuneCountInString(cleaned); opts.MaxLength > 0 && n > opts.MaxLength {
		return "", fmt.Errorf("the text can be at most %d characters (it is %d)", opts.MaxLength, n)
	}
	return cleaned, nil
}

// stripTags removes HTML until nothing changes, so tags hidden behind HTML
// entities (&lt;script&gt;) are removed too. bluemonday returns escaped text;
// it is unescaped again because platypus stores plain text. The final decode
// can themselves introduce a tag, so one last tag strip follows the loop.
func stripTags(text string) string {
	for range 3 {
		stripped := html.UnescapeString(strict.Sanitize(text))
		if stripped == text {
			break
		}
		text = stripped
	}
	return leftoverTags.ReplaceAllString(text, "")
}

// isDirectionControl reports Unicode characters that change text direction.
// They can make text look different from what it is ("Trojan Source").
func isDirectionControl(r rune) bool {
	switch {
	case r >= '\u202A' && r <= '\u202E', // embeddings and overrides
		r >= '\u2066' && r <= '\u2069',              // isolates
		r == '\u200E', r == '\u200F', r == '\u061C': // directional marks
		return true
	}
	return false
}
