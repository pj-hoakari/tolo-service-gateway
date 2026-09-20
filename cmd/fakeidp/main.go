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

	"github.com/pj-hoakari/tolo-service-gateway/internal/fakeidp"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
)

const (
	defaultLogLevel   = "info"
	defaultListenAddr = ":8080"
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
)

const (
	envListenAddr = "SERVER_ADDR"
	envIssuer     = "FAKE_IDP_ISSUER"
	envAudience   = "FAKE_IDP_AUDIENCE"
)

type config struct {
	ListenAddr string
	Issuer     string
	Audience   string
}

func main() {
	if err := run(); err != nil {
		slog.Error("fake idp failed", "error", err)
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

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	slog.Info("fake idp configuration loaded",
		"addr", cfg.ListenAddr,
		"issuer", cfg.Issuer,
		"audience", cfg.Audience,
	)
	slog.Warn("the fake IdP signs tokens without any checks; it is for development only and must not be deployed to a production-like environment")

	handler, err := fakeidp.NewHandler(fakeidp.Config{Issuer: cfg.Issuer, Audience: cfg.Audience})
	if err != nil {
		return fmt.Errorf("build the fake idp handler: %w", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)

	go func() {
		slog.Info("fake idp listening", "addr", cfg.ListenAddr)

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
		slog.Info("fake idp shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		return httpServer.Shutdown(shutdownCtx)
	}
}

func loadConfig(getenv func(string) string) (config, error) {
	listenAddr := getenv(envListenAddr)
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	issuer := getenv(envIssuer)
	audience := getenv(envAudience)

	var errs []error

	if issuer == "" {
		errs = append(errs, missingEnvError(envIssuer))
	}

	if audience == "" {
		errs = append(errs, missingEnvError(envAudience))
	}

	if err := errors.Join(errs...); err != nil {
		var zero config

		return zero, err
	}

	return config{ListenAddr: listenAddr, Issuer: issuer, Audience: audience}, nil
}

func newLogger() (*slog.Logger, error) {
	level, err := logging.ParseLevel(getenv("LOG_LEVEL", defaultLogLevel))
	if err != nil {
		return nil, fmt.Errorf("read LOG_LEVEL: %w", err)
	}

	return logging.NewLogger(os.Stdout, logging.Options{
		Level:     level,
		AddSource: false,
		ProjectID: os.Getenv("GOOGLE_CLOUD_PROJECT"),
	}), nil
}

func missingEnvError(key string) error {
	return fmt.Errorf("%s is required but not set", key)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
