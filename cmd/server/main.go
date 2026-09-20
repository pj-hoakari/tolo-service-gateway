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

	connectrpc "connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"go.opentelemetry.io/otel"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/config"
	"github.com/pj-hoakari/tolo-service-gateway/internal/idp"
	infraconnect "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forward"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forwardgen"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
	"github.com/pj-hoakari/tolo-service-gateway/internal/telemetry"
	"github.com/pj-hoakari/tolo-service-gateway/internal/token"
)

const (
	defaultLogLevel   = "info"
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
)

const (
	signingKeyReadinessCheck = "internal-jwt-signing-key"
	idpReadinessCheck        = "idp-discovery"
)

var (
	errSigningKeyNotLoaded = errors.New("the internal JWT signing key is not loaded")
	errUnexpectedTransport = errors.New("the default HTTP transport is not an *http.Transport")
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

	slog.Info("gateway configuration loaded", configLogAttrs(cfg)...)
	slog.Warn("workload authentication is not implemented yet; do not deploy this build to a production-like environment")

	shutdownTracing, err := telemetry.Setup(ctx)
	if err != nil {
		return fmt.Errorf("setup tracing: %w", err)
	}
	defer shutdownTracingWithTimeout(shutdownTracing)

	if telemetry.Enabled() {
		slog.Info("tracing enabled", "service", telemetry.ServiceName())
	}

	rpcRegistry, destinations, err := buildRegistry(cfg)
	if err != nil {
		return err
	}

	slog.Info("rpc registry built",
		"procedures", len(rpcRegistry.Entries()),
		"destinations", rpcRegistry.Destinations(),
	)

	rpcHandlers, err := buildRPCHandlers(destinations)
	if err != nil {
		return err
	}

	internalIssuer, signingKeys, err := token.NewIssuerFromFiles(cfg.IssuerID, internalJWTKeyFiles(cfg))
	if err != nil {
		return fmt.Errorf("build internal JWT issuer: %w", err)
	}

	readiness := httpapi.NewReadiness()
	readiness.Register(signingKeyReadinessCheck, signingKeyCheck(signingKeys))

	authenticator := authn.NewAuthenticator(nil, nil)
	idpErr := make(chan error, 1)

	if cfg.IDPIssuer == "" {
		slog.Warn("external token verification is disabled because IDP_ISSUER is not set; every request that carries credentials is rejected as unauthenticated")
	} else {
		provider, err := idp.New(idp.Config{
			Issuer:                    cfg.IDPIssuer,
			Audience:                  cfg.IDPAudience,
			Algorithms:                cfg.IDPAlgorithms,
			IntrospectionClientID:     cfg.IDPIntrospectionClientID,
			IntrospectionClientSecret: cfg.IDPIntrospectionSecret,
			LegacyEventsWriteScope:    cfg.IDPLegacyEventsWriteScope,
			HTTPClient:                idp.NewHTTPClient(),
			RetryDelay:                0,
			Clock:                     nil,
		})
		if err != nil {
			return fmt.Errorf("build the external token verifier: %w", err)
		}

		var introspector authn.Introspector

		if cfg.IDPIntrospectionClientID == "" {
			slog.Warn("token introspection is disabled because IDP_INTROSPECTION_CLIENT_ID is not set; the administrative write RPCs are rejected as unauthenticated")
		} else {
			introspector = provider
		}

		if cfg.IDPLegacyEventsWriteScope {
			slog.Warn("the transitional scope rewrite is enabled by IDP_LEGACY_EVENTS_WRITE_SCOPE; every external token carrying events.write is treated as carrying events.manage, events.operate and events.report; turn it off once the IdP issues the new scopes")
		}

		authenticator = authn.NewAuthenticator(provider, introspector)

		readiness.Register(idpReadinessCheck, provider.Ready)

		go func() {
			if err := provider.Run(ctx); err != nil {
				idpErr <- err
			}
		}()
	}

	handler := httpapi.NewHandler(
		httpapi.HealthRoutes(readiness),
		httpapi.PublicRoutes(httpapi.NewJWKSHandler(internalIssuer)),
		httpapi.WorkloadRoutes(),
		infraconnect.Routes(infraconnect.Config{
			Registry:         rpcRegistry,
			Handlers:         rpcHandlers,
			Audit:            newAuditEmitter(),
			Authenticator:    authenticator,
			Issuer:           internalIssuer,
			TracerProvider:   otel.GetTracerProvider(),
			TrustedProxyHops: cfg.TrustedProxyHops,
		}),
	)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
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
	case err := <-idpErr:
		return fmt.Errorf("resolve the IdP metadata: %w", err)
	case <-ctx.Done():
		slog.Info("server shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		return httpServer.Shutdown(shutdownCtx)
	}
}

func buildRegistry(cfg config.Config) (*registry.Registry, registry.Destinations, error) {
	rpcRegistry, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		return nil, nil, fmt.Errorf("build the RPC registry: %w", err)
	}

	destinations, err := registry.LoadDestinations(cfg.DestinationsFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load the destinations: %w", err)
	}

	if err := rpcRegistry.CheckDestinations(destinations); err != nil {
		return nil, nil, fmt.Errorf("check the destinations: %w", err)
	}

	return rpcRegistry, destinations, nil
}

func buildRPCHandlers(destinations registry.Destinations) (map[string]http.Handler, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errUnexpectedTransport
	}

	tracing, err := otelconnect.NewInterceptor(
		otelconnect.WithTracerProvider(otel.GetTracerProvider()),
		otelconnect.WithPropagator(otel.GetTextMapPropagator()),
	)
	if err != nil {
		return nil, fmt.Errorf("build the tracing interceptor: %w", err)
	}

	handlers, err := forward.Handlers(
		catalog.Bindings(),
		destinations,
		forwardgen.Mounts(),
		forward.NewHTTPClient(transport.Clone()),
		[]connectrpc.ClientOption{connectrpc.WithInterceptors(tracing, forward.AuthorizationInterceptor())},
		[]connectrpc.HandlerOption{connectrpc.WithInterceptors(infraconnect.AuditInterceptor())},
	)
	if err != nil {
		return nil, fmt.Errorf("build the RPC handlers: %w", err)
	}

	return handlers, nil
}

func newAuditEmitter() *audit.Emitter {
	return audit.NewEmitter(logging.NewLogger(os.Stdout, logging.Options{
		Level:     slog.LevelInfo,
		AddSource: false,
		ProjectID: os.Getenv("GOOGLE_CLOUD_PROJECT"),
	}))
}

func internalJWTKeyFiles(cfg config.Config) token.FileKeys {
	published := make([]issuer.KeyFile, 0, len(cfg.PublishedKeys))

	for _, key := range cfg.PublishedKeys {
		published = append(published, issuer.KeyFile{Path: key.Path, KeyID: key.ID})
	}

	return token.FileKeys{
		Signing:   issuer.KeyFile{Path: cfg.SigningKey.Path, KeyID: cfg.SigningKey.ID},
		Published: published,
	}
}

func configLogAttrs(cfg config.Config) []any {
	publishedKeyIDs := make([]string, 0, len(cfg.PublishedKeys))

	for _, key := range cfg.PublishedKeys {
		publishedKeyIDs = append(publishedKeyIDs, key.ID)
	}

	attrs := []any{
		"addr", cfg.ListenAddr,
		"issuer", cfg.IssuerID,
		"signing_key_file", cfg.SigningKey.Path,
		"signing_kid", cfg.SigningKey.ID,
		"published_kids", publishedKeyIDs,
		"destinations_file", cfg.DestinationsFile,
		"trusted_proxy_hops", cfg.TrustedProxyHops,
	}

	if cfg.IDPIssuer != "" {
		attrs = append(attrs,
			"idp_issuer", cfg.IDPIssuer,
			"idp_audience", cfg.IDPAudience,
			"idp_algorithms", cfg.IDPAlgorithms,
			"idp_legacy_events_write_scope", cfg.IDPLegacyEventsWriteScope,
		)
	}

	if cfg.IDPIntrospectionClientID != "" {
		attrs = append(attrs,
			"idp_introspection_client_id", cfg.IDPIntrospectionClientID,
			"idp_introspection_client_secret_file", cfg.IDPIntrospectionSecretFile,
		)
	}

	return attrs
}

func signingKeyCheck(keys issuer.KeyProvider) httpapi.ReadinessCheck {
	return func(ctx context.Context) error {
		keySet, err := keys.Current(ctx)
		if err != nil {
			return fmt.Errorf("read the internal JWT key files: %w", err)
		}

		if keySet.Signing.Key == nil {
			return errSigningKeyNotLoaded
		}

		return nil
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
