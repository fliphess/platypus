package authz

import (
	"errors"
	"strings"
	"unicode"
)

// Pattern selects items by name: either an exact name, or a prefix followed
// by a single '*' at the end that matches everything below it.
//
//	/apps/payments/db-password   exactly this name
//	/apps/payments/*             everything starting with /apps/payments/
//	*                            everything
type Pattern struct {
	text string
}

const maxPatternLength = 2048

// ParsePattern validates and parses a pattern.
func ParsePattern(text string) (Pattern, error) {
	switch {
	case text == "":
		return Pattern{}, errors.New("the pattern can't be empty")
	case len(text) > maxPatternLength:
		return Pattern{}, errors.New("the pattern can be at most 2048 characters")
	case strings.IndexFunc(text, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return Pattern{}, errors.New("the pattern can't contain spaces or control characters")
	case strings.Contains(strings.TrimSuffix(text, "*"), "*"):
		return Pattern{}, errors.New("a * is only allowed at the end of the pattern")
	}
	return Pattern{text: text}, nil
}

// MustParsePattern is ParsePattern for patterns known to be valid, such as
// constants and values read back from the database. It panics on bad input.
func MustParsePattern(text string) Pattern {
	p, err := ParsePattern(text)
	if err != nil {
		panic("invalid pattern " + text + ": " + err.Error())
	}
	return p
}

// String returns the pattern as written.
func (p Pattern) String() string {
	return p.text
}

// IsPrefix reports whether the pattern ends in '*'.
func (p Pattern) IsPrefix() bool {
	return strings.HasSuffix(p.text, "*")
}

// Literal returns the pattern without its trailing '*': the exact name, or the
// prefix every matching name starts with.
func (p Pattern) Literal() string {
	return strings.TrimSuffix(p.text, "*")
}

// Matches reports whether name is selected by the pattern.
func (p Pattern) Matches(name string) bool {
	if p.IsPrefix() {
		return strings.HasPrefix(name, p.Literal())
	}
	return name == p.text
}
