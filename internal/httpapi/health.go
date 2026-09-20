package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"sync"
)

type ReadinessCheck func(ctx context.Context) error

type readinessEntry struct {
	name  string
	check ReadinessCheck
}

type Readiness struct {
	mu      sync.RWMutex
	entries []readinessEntry
}

func NewReadiness() *Readiness {
	return &Readiness{
		mu:      sync.RWMutex{},
		entries: nil,
	}
}

func (r *Readiness) Register(name string, check ReadinessCheck) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = append(r.entries, readinessEntry{name: name, check: check})
}

func (r *Readiness) snapshot() []readinessEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return slices.Clone(r.entries)
}

func HealthRoutes(readiness *Readiness) Routes {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("GET /healthz", handleHealthz)
		mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			handleReadyz(w, r, readiness)
		})
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte("ok")); err != nil {
		slog.ErrorContext(r.Context(), "healthz response write failed", "error", err)
	}
}

func handleReadyz(w http.ResponseWriter, r *http.Request, readiness *Readiness) {
	ctx := r.Context()

	status, body := http.StatusOK, "ok"

	for _, entry := range readiness.snapshot() {
		if err := entry.check(ctx); err != nil {
			slog.WarnContext(ctx, "readiness check failed", "check", entry.name, "error", err)

			status, body = http.StatusServiceUnavailable, "not ready"
		}
	}

	w.WriteHeader(status)

	if _, err := w.Write([]byte(body)); err != nil {
		slog.ErrorContext(ctx, "readyz response write failed", "error", err)
	}
}
