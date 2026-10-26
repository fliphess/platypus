// Package health serves the Kubernetes probes on their own listener, which is
// never exposed through the Service or the gateway.
package health

import (
	"context"
	"net/http"
	"time"
)

// Pinger is anything that can check its connection, like a pgxpool.Pool.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Handler returns the probe endpoints:
//
//	/healthz  liveness: the process answers, and alive (if set) reports no error
//	/readyz   readiness: the database answers too
func Handler(db Pinger, alive func() error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if alive != nil {
			if err := alive(); err != nil {
				writeStatus(w, http.StatusServiceUnavailable, err.Error())
				return
			}
		}
		writeStatus(w, http.StatusOK, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			writeStatus(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeStatus(w, http.StatusOK, "ready")
	})
	return mux
}

func writeStatus(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(text + "\n"))
}
