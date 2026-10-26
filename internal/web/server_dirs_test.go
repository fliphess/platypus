package web

import (
	"testing"

	"go.uber.org/zap"
)

func TestNewServerRefusesMissingDirs(t *testing.T) {
	services := Services{}
	settings := Settings{TemplatesDir: "templates", StaticDir: "static"}
	log := zap.NewNop()

	broken := settings
	broken.TemplatesDir = t.TempDir() // exists but has no templates
	if _, err := NewServer(services, broken, log); err == nil {
		t.Error("a templates directory without templates should be refused")
	}

	broken = settings
	broken.StaticDir = "does-not-exist"
	if _, err := NewServer(services, broken, log); err == nil {
		t.Error("a missing static directory should be refused")
	}

	broken = settings
	broken.StaticDir = "server.go"
	if _, err := NewServer(services, broken, log); err == nil {
		t.Error("a file in place of the static directory should be refused")
	}
}
