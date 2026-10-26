// Package sensitive provides a type for secret values that refuses to leak.
//
// Parameter values, secret values and credentials only ever live in a Value.
// Every way Go can turn a Value into text (fmt verbs, JSON, text encoding,
// slog, zap) prints [REDACTED] instead of the contents. The only way to get
// the contents is an explicit call to Reveal, which makes every place that
// handles a real value easy to find and review.
package sensitive

import (
	"fmt"
	"log/slog"

	"go.uber.org/zap/zapcore"
)

// Redacted is what a Value prints instead of its contents.
const Redacted = "[REDACTED]"

// Value holds a secret. The zero Value is empty.
//
// The contents sit behind a pointer on purpose: when a Value is an unexported
// field of another struct, fmt cannot call its methods and prints the field
// raw. A pointer is printed as an address, never as the text it points to.
type Value struct {
	box *box
}

type box struct {
	text string
}

// New wraps text in a Value.
func New(text string) Value {
	return Value{box: &box{text: text}}
}

// Reveal returns the contents. Only call it where the value must leave the
// process: towards AWS, or towards the browser of a user who may see it.
func (v Value) Reveal() string {
	if v.box == nil {
		return ""
	}
	return v.box.text
}

// IsEmpty reports whether the Value holds no text.
func (v Value) IsEmpty() bool {
	return v.Reveal() == ""
}

// Len returns the length of the contents in bytes.
func (v Value) Len() int {
	return len(v.Reveal())
}

// String implements fmt.Stringer.
func (v Value) String() string { return Redacted }

// GoString implements fmt.GoStringer, used by the %#v verb.
func (v Value) GoString() string { return Redacted }

// Format implements fmt.Formatter, so every verb (%v, %s, %q, %x, ...) prints
// the redacted text.
func (v Value) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(Redacted))
}

// MarshalJSON implements json.Marshaler.
func (v Value) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Redacted + `"`), nil
}

// MarshalText implements encoding.TextMarshaler.
func (v Value) MarshalText() ([]byte, error) {
	return []byte(Redacted), nil
}

// LogValue implements slog.LogValuer.
func (v Value) LogValue() slog.Value {
	return slog.StringValue(Redacted)
}

// MarshalLogObject implements zapcore.ObjectMarshaler, used by zap.Object.
func (v Value) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("value", Redacted)
	return nil
}
