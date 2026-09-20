package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pj-hoakari/tolo-service-gateway/internal/config"
	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
	"github.com/pj-hoakari/tolo-service-gateway/internal/telemetry"
)

const (
	defaultLogLevel   = "info"
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		// run() installs the default logger itself, so a failure before that
		// point is reported by slog's own handler on stderr instead.
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	logger, err := newLogger()
	if err != nil {
		return err
	}

	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	slog.Info("gateway configuration loaded",
		"addr", cfg.ListenAddr,
		"issuer", cfg.IssuerID,
		"signing_key_file", cfg.SigningKeyFile,
	)
	slog.Warn("workload authentication is not implemented yet; do not deploy this build to a production-like environment")

	shutdownTracing, err := telemetry.Setup(ctx)
	if err != nil {
		return fmt.Errorf("setup tracing: %w", err)
	}
	defer shutdownTracingWithTimeout(shutdownTracing)

	if telemetry.Enabled() {
		slog.Info("tracing enabled", "service", telemetry.ServiceName())
	}

	readiness := httpapi.NewReadiness()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.NewHandler(readiness),
		ReadHeaderTimeout: readHeaderTimeout,
		// net/http reports its own failures (a broken connection, a panic in a
		// handler) through this logger, so it goes to the same structured
		// stream as everything else.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)

	go func() {
		slog.Info("server listening", "addr", cfg.ListenAddr)

		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err

			return
		}

		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		slog.Info("server shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		return httpServer.Shutdown(shutdownCtx)
	}
}

// newLogger builds the process logger from the environment. It is the first
// thing run() does, so that everything the service reports afterwards is
// written in the structure Cloud Logging parses.
func newLogger() (*slog.Logger, error) {
	level, err := logging.ParseLevel(getenv("LOG_LEVEL", defaultLogLevel))
	if err != nil {
		return nil, fmt.Errorf("read LOG_LEVEL: %w", err)
	}

	return logging.NewLogger(os.Stdout, logging.Options{
		Level:     level,
		AddSource: false,
		// Without a project the log entries carry the bare trace ID, so Cloud
		// Logging cannot correlate them with the trace.
		ProjectID: os.Getenv("GOOGLE_CLOUD_PROJECT"),
	}), nil
}

// shutdownTracingWithTimeout flushes pending spans on a fresh context, because
// the run context is already cancelled once the process starts shutting down.
func shutdownTracingWithTimeout(shutdown telemetry.ShutdownFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := shutdown(ctx); err != nil {
		slog.Error("shutdown tracing failed", "error", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
