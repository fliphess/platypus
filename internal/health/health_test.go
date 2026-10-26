package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

func TestHealth(t *testing.T) {
	tests := []struct {
		path  string
		db    pinger
		alive func() error
		want  int
	}{
		{"/healthz", pinger{errors.New("down")}, nil, http.StatusOK},
		{"/healthz", pinger{}, func() error { return nil }, http.StatusOK},
		{"/healthz", pinger{}, func() error { return errors.New("stuck") }, http.StatusServiceUnavailable},
		{"/readyz", pinger{}, nil, http.StatusOK},
		{"/readyz", pinger{errors.New("down")}, nil, http.StatusServiceUnavailable},
		{"/other", pinger{}, nil, http.StatusNotFound},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		Handler(tt.db, tt.alive).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if rec.Code != tt.want {
			t.Errorf("GET %s = %d, want %d", tt.path, rec.Code, tt.want)
		}
	}
}
