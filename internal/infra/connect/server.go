// Package connect provides the Connect HTTP transport for this service.
package connect

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	connectrpc "connectrpc.com/connect"
	"connectrpc.com/otelconnect"

	"github.com/pj-hoakari/internal-jwt-handling/interceptor"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	"github.com/pj-hoakari/go-service-template/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/go-service-template/internal/application"
)

// Defaults for verifying internal JWTs. The issuer is the Service Gateway's
// issuer identifier and must match the value the gateway signs with; the
// audience is this service's logical identifier.
const (
	DefaultInternalJWKSURL     = "http://gateway:8080/.well-known/jwks.json"
	DefaultInternalJWTIssuer   = "service-gateway"
	DefaultInternalJWTAudience = "go-service-template"
)

// JWTSettings locates the Service Gateway's JWKS and names the issuer and
// audience every internal JWT must carry.
type JWTSettings struct {
	JWKSURL  string
	Issuer   string
	Audience string
}

// DefaultJWTSettings returns the settings for the Docker Compose setup;
// cmd/server overrides them from the environment.
func DefaultJWTSettings() JWTSettings {
	return JWTSettings{
		JWKSURL:  DefaultInternalJWKSURL,
		Issuer:   DefaultInternalJWTIssuer,
		Audience: DefaultInternalJWTAudience,
	}
}

// NewHandlerWithJWTSettings builds the process handler that verifies internal
// JWTs against the JWKS the settings locate.
func NewHandlerWithJWTSettings(greetService application.GreetUseCases, settings JWTSettings) (http.Handler, error) {
	cache, err := jwks.New(jwks.Config{
		URL:             settings.JWKSURL,
		HTTPClient:      nil,
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    0,
		RetryBackoff:    nil,
		MaxDocumentSize: 0,
	})
	if err != nil {
		return nil, fmt.Errorf("create JWKS cache: %w", err)
	}

	tokenVerifier, err := verifier.New(settings.Issuer, settings.Audience, cache)
	if err != nil {
		return nil, fmt.Errorf("create internal JWT verifier: %w", err)
	}

	return NewHandlerWithVerifier(greetService, tokenVerifier)
}

// NewHandlerWithVerifier builds the process handler around a verifier of the
// internal JWT. The service is guarded by an interceptor built from its
// generated policy table, so the credential rules stay declared in the proto.
func NewHandlerWithVerifier(greetService application.GreetUseCases, tokenVerifier interceptor.TokenVerifier) (http.Handler, error) {
	// The caller sits behind the Service Gateway, so an incoming trace context is
	// trusted and continued instead of being demoted to a span link.
	tracing, err := otelconnect.NewInterceptor(otelconnect.WithTrustRemote())
	if err != nil {
		return nil, fmt.Errorf("create tracing interceptor: %w", err)
	}

	auth, err := interceptor.New(
		tokenVerifier,
		greetv1connect.GreetServicePolicies,
		interceptor.WithErrorReporter(reportAuthRejection),
	)
	if err != nil {
		return nil, fmt.Errorf("create GreetService authentication interceptor: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)

	// Tracing runs before authentication, so a rejected call is still recorded
	// on the trace it belongs to.
	path, handler := greetv1connect.NewGreetServiceHandler(
		NewService(greetService),
		connectrpc.WithInterceptors(tracing, auth),
	)
	mux.Handle(path, handler)

	return mux, nil
}

// reportAuthRejection logs why a call was refused. The client only ever learns
// the Connect code, so the cause is kept server-side, on the trace of the
// request context.
func reportAuthRejection(ctx context.Context, procedure string, err error) {
	slog.WarnContext(ctx, "internal JWT rejected", "procedure", procedure, "error", err)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte("ok")); err != nil {
		slog.ErrorContext(r.Context(), "healthz response write failed", "error", err)
	}
}
