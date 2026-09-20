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

	"github.com/pj-hoakari/internal-jwt-handling/interceptor"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
	"github.com/pj-hoakari/tolo-service-gateway/internal/testbackend"
)

const (
	defaultLogLevel   = "info"
	defaultListenAddr = ":8080"
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
)

const (
	envListenAddr = "SERVER_ADDR"
	envJWKSURL    = "INTERNAL_JWKS_URL"
	envIssuerID   = "INTERNAL_JWT_ISSUER"
	envAudience   = "INTERNAL_JWT_AUDIENCE"
)

type config struct {
	ListenAddr string
	JWKSURL    string
	IssuerID   string
	Audience   string
}

func main() {
	if err := run(); err != nil {
		slog.Error("test backend failed", "error", err)
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

	slog.Info("test backend configuration loaded",
		"addr", cfg.ListenAddr,
		"jwks_url", cfg.JWKSURL,
		"issuer", cfg.IssuerID,
		"audience", cfg.Audience,
	)

	tokenVerifier, err := newTokenVerifier(cfg)
	if err != nil {
		return err
	}

	handler, err := testbackend.NewHandler(tokenVerifier)
	if err != nil {
		return fmt.Errorf("build the test backend handler: %w", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}

	serveErr := make(chan error, 1)

	go func() {
		slog.Info("test backend listening", "addr", cfg.ListenAddr)

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
		slog.Info("test backend shutting down")

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

	jwksURL := getenv(envJWKSURL)
	issuerID := getenv(envIssuerID)
	audience := getenv(envAudience)

	var errs []error

	if jwksURL == "" {
		errs = append(errs, missingEnvError(envJWKSURL))
	}

	if issuerID == "" {
		errs = append(errs, missingEnvError(envIssuerID))
	}

	if audience == "" {
		errs = append(errs, missingEnvError(envAudience))
	}

	if err := errors.Join(errs...); err != nil {
		var zero config

		return zero, err
	}

	return config{
		ListenAddr: listenAddr,
		JWKSURL:    jwksURL,
		IssuerID:   issuerID,
		Audience:   audience,
	}, nil
}

func newTokenVerifier(cfg config) (interceptor.TokenVerifier, error) {
	cache, err := jwks.New(jwks.Config{
		URL:             cfg.JWKSURL,
		HTTPClient:      nil,
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    0,
		RetryBackoff:    nil,
		MaxDocumentSize: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("create the JWKS cache: %w", err)
	}

	tokenVerifier, err := verifier.New(cfg.IssuerID, cfg.Audience, cache)
	if err != nil {
		return nil, fmt.Errorf("create the internal JWT verifier: %w", err)
	}

	return tokenVerifier, nil
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
