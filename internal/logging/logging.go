// Package logging sets up structured JSON logging to stdout, for your log
// collector. Nothing logs values: they only exist as sensitive.Value, which
// prints as [REDACTED].
package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New returns a JSON logger at the given level (debug, info, warn, error).
func New(level string) (*zap.Logger, error) {
	parsed, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, err
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(parsed)
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.MessageKey = "message"
	// Stack traces on errors would only repeat what the error says.
	cfg.DisableStacktrace = true
	return cfg.Build(zap.Fields(zap.String("service", "platypus")))
}
