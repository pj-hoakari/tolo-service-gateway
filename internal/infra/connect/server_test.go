package connect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	greetv1 "github.com/pj-hoakari/go-service-template/gen/greet/v1"
	"github.com/pj-hoakari/go-service-template/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/go-service-template/internal/application"
	"github.com/pj-hoakari/go-service-template/internal/domain"
	"github.com/pj-hoakari/go-service-template/internal/tenantctx"
)

// newTestJWKSURL serves keys from an httptest endpoint, mirroring the Service
// Gateway publishing its signing keys, and returns the URL to fetch them from.
func newTestJWKSURL(t *testing.T, keys internaljwt.JWKS) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(keys); err != nil {
			t.Errorf("encode JWKS: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	return server.URL
}

// newTestVerifier builds a verifier backed by an httptest JWKS endpoint serving
// keys.
func newTestVerifier(t *testing.T, keys internaljwt.JWKS) *verifier.Verifier {
	t.Helper()

	// The cooldowns are collapsed so that a refresh on an unknown kid is never
	// held off within a test run.
	cache, err := jwks.New(jwks.Config{
		URL:             newTestJWKSURL(t, keys),
		RefreshCooldown: time.Nanosecond,
		FailureCooldown: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("create JWKS cache: %v", err)
	}

	tokenVerifier, err := verifier.New(DefaultInternalJWTIssuer, DefaultInternalJWTAudience, cache)
	if err != nil {
		t.Fatalf("create internal JWT verifier: %v", err)
	}

	return tokenVerifier
}

// newTestHandler builds the production handler wired to a verifier trusting
// keys, serving greetService.
func newTestHandler(t *testing.T, keys internaljwt.JWKS, greetService application.GreetUseCases) http.Handler {
	t.Helper()

	handler, err := NewHandlerWithVerifier(greetService, newTestVerifier(t, keys))
	if err != nil {
		t.Fatalf("NewHandlerWithVerifier() error = %v", err)
	}

	return handler
}

// mintInternalJWT issues an internal JWT for the issuer and audience this
// service verifies against.
func mintInternalJWT(t *testing.T, tokenUse, scope, tenantPublicID string) (string, internaljwt.JWKS) {
	t.Helper()

	return mintInternalJWTFor(t, DefaultInternalJWTIssuer, DefaultInternalJWTAudience, tokenUse, scope, tenantPublicID)
}

// mintInternalJWTFor issues an internal JWT signed by a fresh key, returning
// the Authorization header value and the JWKS document publishing the key. An
// empty tenantPublicID omits the tenant_id claim.
func mintInternalJWTFor(t *testing.T, issuer, audience, tokenUse, scope, tenantPublicID string) (string, internaljwt.JWKS) {
	t.Helper()

	output, err := jwtgen.Generate(jwtgen.Config{
		Issuer:         issuer,
		Audience:       audience,
		TokenUse:       tokenUse,
		TenantPublicID: tenantPublicID,
		Scope:          scope,
		KeyID:          "test-key",
		TTL:            time.Hour,
	})
	if err != nil {
		t.Fatalf("generate internal JWT: %v", err)
	}

	return "Bearer " + output.Token, output.JWKS
}

func TestNewHandlerWithJWTSettings(t *testing.T) {
	t.Parallel()

	t.Run("verifies a token against the JWKS the settings locate", func(t *testing.T) {
		t.Parallel()

		authorization, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")

		settings := DefaultJWTSettings()
		settings.JWKSURL = newTestJWKSURL(t, keys)

		handler, err := NewHandlerWithJWTSettings(application.NewGreetService(), settings)
		if err != nil {
			t.Fatalf("NewHandlerWithJWTSettings() error = %v", err)
		}

		httpServer := httptest.NewServer(handler)
		t.Cleanup(httpServer.Close)
		client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

		req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
		req.Header().Set("Authorization", authorization)

		res, err := client.Greet(context.Background(), req)
		if err != nil {
			t.Fatalf("Greet() error = %v", err)
		}

		if got, want := res.Msg.GetGreeting(), "Hello, Ada!"; got != want {
			t.Errorf("Greeting = %q, want %q", got, want)
		}
	})

	t.Run("rejects settings without a JWKS URL", func(t *testing.T) {
		t.Parallel()

		settings := DefaultJWTSettings()
		settings.JWKSURL = ""

		_, err := NewHandlerWithJWTSettings(application.NewGreetService(), settings)
		if !errors.Is(err, jwks.ErrMissingURL) {
			t.Fatalf("NewHandlerWithJWTSettings() error = %v, want %v", err, jwks.ErrMissingURL)
		}
	})
}

func TestGreetServiceAuthz(t *testing.T) {
	t.Parallel()

	authorization, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	httpServer := httptest.NewServer(newTestHandler(t, keys, application.NewGreetService()))
	t.Cleanup(httpServer.Close)
	client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

	t.Run("rejects missing bearer token", func(t *testing.T) {
		_, err := client.Greet(context.Background(), connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"}))
		if connectrpc.CodeOf(err) != connectrpc.CodeUnauthenticated {
			t.Fatalf("Greet() error code = %v, want %v", connectrpc.CodeOf(err), connectrpc.CodeUnauthenticated)
		}
	})

	t.Run("accepts internal JWT with required scope", func(t *testing.T) {
		req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
		req.Header().Set("Authorization", authorization)

		res, err := client.Greet(context.Background(), req)
		if err != nil {
			t.Fatalf("Greet() error = %v", err)
		}

		if got, want := res.Msg.GetGreeting(), "Hello, Ada!"; got != want {
			t.Errorf("Greeting = %q, want %q", got, want)
		}
	})
}

func TestGreetServiceAuthzRejectsMissingScope(t *testing.T) {
	t.Parallel()

	authorization, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.write", "a1b2c3d4e5f60718")
	httpServer := httptest.NewServer(newTestHandler(t, keys, application.NewGreetService()))
	t.Cleanup(httpServer.Close)
	client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
	req.Header().Set("Authorization", authorization)

	_, err := client.Greet(context.Background(), req)
	if got, want := connectrpc.CodeOf(err), connectrpc.CodePermissionDenied; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

func TestGreetServiceAuthzRejectsUnknownSigningKey(t *testing.T) {
	t.Parallel()

	// The handler trusts a JWKS publishing neither the key nor the kid that
	// signed the token below.
	_, trustedKeys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	for i := range trustedKeys.Keys {
		trustedKeys.Keys[i].KeyID = "other-key"
	}

	foreignAuthorization, _ := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	httpServer := httptest.NewServer(newTestHandler(t, trustedKeys, application.NewGreetService()))
	t.Cleanup(httpServer.Close)
	client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
	req.Header().Set("Authorization", foreignAuthorization)

	_, err := client.Greet(context.Background(), req)
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeUnauthenticated; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

func TestGreetServiceAuthzRejectsServiceToken(t *testing.T) {
	t.Parallel()

	// AUTH_LEVEL_AUTHENTICATED admits the default token_use only, so a service
	// token is not a credential for this RPC.
	authorization, keys := mintInternalJWT(t, internaljwt.TokenUseService, "", "")
	httpServer := httptest.NewServer(newTestHandler(t, keys, application.NewGreetService()))
	t.Cleanup(httpServer.Close)
	client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
	req.Header().Set("Authorization", authorization)

	_, err := client.Greet(context.Background(), req)
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeUnauthenticated; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

func TestGreetServiceAuthzRejectsAudienceMismatch(t *testing.T) {
	t.Parallel()

	// The token names another service as its audience, so it is not a
	// credential this service may accept even though the key verifies.
	authorization, keys := mintInternalJWTFor(
		t,
		DefaultInternalJWTIssuer,
		"other-service",
		internaljwt.TokenUseTenantAccess,
		"greeting.read",
		"a1b2c3d4e5f60718",
	)
	httpServer := httptest.NewServer(newTestHandler(t, keys, application.NewGreetService()))
	t.Cleanup(httpServer.Close)
	client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
	req.Header().Set("Authorization", authorization)

	_, err := client.Greet(context.Background(), req)
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeUnauthenticated; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

// tenantEchoService greets the tenant public ID found in the request context,
// letting the test observe the verified tenant_id claim reaching the handler
// without changing the real greet service.
type tenantEchoService struct{}

func (tenantEchoService) Greet(ctx context.Context, _ application.GreetInput) (domain.Greeting, error) {
	tenantPublicID, _ := tenantctx.TenantPublicIDFromContext(ctx)

	return domain.NewGreeting(tenantPublicID)
}

func TestGreetServiceInjectsTenantPublicID(t *testing.T) {
	t.Parallel()

	authorization, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	httpServer := httptest.NewServer(newTestHandler(t, keys, tenantEchoService{}))
	t.Cleanup(httpServer.Close)
	client := greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
	req.Header().Set("Authorization", authorization)

	res, err := client.Greet(context.Background(), req)
	if err != nil {
		t.Fatalf("Greet() error = %v", err)
	}

	if got, want := res.Msg.GetGreeting(), "Hello, a1b2c3d4e5f60718!"; got != want {
		t.Errorf("tenant ID echoed by handler = %q, want %q", got, want)
	}
}
