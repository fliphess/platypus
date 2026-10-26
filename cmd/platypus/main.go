// Command platypus manages SSM parameters and Secrets Manager secrets
// through a web interface, so people don't need AWS access to do so.
//
// Usage:
//
//	platypus web              serve the user interface
//	platypus worker           run the background jobs
//	platypus reset-bootstrap  issue a new bootstrap token (run with kubectl exec)
//
// All settings come from environment variables; see internal/docs/pages/90-configuration.txt.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata" // the zone database travels with the binary

	"go.uber.org/zap"

	"platypus/internal/app"
	"platypus/internal/config"
	"platypus/internal/logging"
)

const usage = "usage: platypus web | worker | reset-bootstrap"

// version is stamped at build time: -ldflags "-X main.version=<git tag>".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "platypus:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New(usage)
	}
	command := args[0]
	switch command {
	case "web", "worker", "reset-bootstrap":
	default:
		return errors.New(usage)
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log, err := logging.New(cfg.LogLevel)
	if err != nil {
		return err
	}
	log.Info("platypus", zap.String("version", version))
	defer func() { _ = log.Sync() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	platypus, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer platypus.Close()

	switch command {
	case "web":
		return platypus.RunWeb(ctx)
	case "worker":
		return platypus.RunWorker(ctx)
	default:
		return platypus.ResetBootstrap(ctx)
	}
}
