package logging

import (
	"testing"

	"go.uber.org/zap"
)

// The independent audit copy must survive a quiet application log level, and
// neither logger may sample.
func TestAuditLoggerIgnoresTheApplicationLevel(t *testing.T) {
	app, err := New("error")
	if err != nil {
		t.Fatal(err)
	}
	if app.Core().Enabled(zap.InfoLevel) {
		t.Error("the application logger ignores its configured level")
	}
	audit := NewAudit()
	if !audit.Core().Enabled(zap.InfoLevel) {
		t.Error("the audit logger drops info records")
	}
	if audit.Core().Enabled(zap.DebugLevel) {
		t.Error("the audit logger is noisier than it needs to be")
	}
}

func TestBadLevelIsRefused(t *testing.T) {
	if _, err := New("chatty"); err == nil {
		t.Error("an unknown level was accepted")
	}
}
