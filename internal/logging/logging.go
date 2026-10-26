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
	return build(parsed)
}

// NewAudit returns the logger for the independent audit copy. It always
// writes at info and is never sampled, whatever the application log level is:
// an audit record must not disappear because the operator chose a quieter
// application log.
func NewAudit() *zap.Logger {
	logger, err := build(zapcore.InfoLevel)
	if err != nil {
		// The fixed level and encoder cannot fail; fall back to a no-op so a
		// caller can never panic, and the database copy still applies.
		return zap.NewNop()
	}
	return logger
}

func build(level zapcore.Level) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	// Sampling drops repeated entries, including audit records. Every audit
	// event is independent, so it must never be sampled.
	cfg.Sampling = nil
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.MessageKey = "message"
	// Stack traces on errors would only repeat what the error says.
	cfg.DisableStacktrace = true
	return cfg.Build(zap.Fields(zap.String("service", "platypus")))
}
