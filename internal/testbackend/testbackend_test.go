package testbackend_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/testbackend"
)

const (
	testIssuer   = "service-gateway"
	testAudience = "tolo-service-gateway"
)

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

func newTestVerifier(t *testing.T, keys internaljwt.JWKS) *verifier.Verifier {
	t.Helper()

	cache, err := jwks.New(jwks.Config{
		URL:             newTestJWKSURL(t, keys),
		RefreshCooldown: time.Nanosecond,
		FailureCooldown: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("create JWKS cache: %v", err)
	}

	tokenVerifier, err := verifier.New(testIssuer, testAudience, cache)
	if err != nil {
		t.Fatalf("create internal JWT verifier: %v", err)
	}

	return tokenVerifier
}

func newTestClient(t *testing.T, keys internaljwt.JWKS) greetv1connect.GreetServiceClient {
	t.Helper()

	handler, err := testbackend.NewHandler(newTestVerifier(t, keys))
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)

	return greetv1connect.NewGreetServiceClient(httpServer.Client(), httpServer.URL)
}

func mintInternalJWT(t *testing.T, tokenUse, scope, tenantPublicID string) (string, internaljwt.JWKS) {
	t.Helper()

	output, err := jwtgen.Generate(jwtgen.Config{
		Issuer:         testIssuer,
		Audience:       testAudience,
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

func TestGreetAcceptsInternalJWT(t *testing.T) {
	t.Parallel()

	authorization, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	client := newTestClient(t, keys)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
	req.Header().Set("Authorization", authorization)

	res, err := client.Greet(context.Background(), req)
	if err != nil {
		t.Fatalf("Greet() error = %v", err)
	}

	if got, want := res.Msg.GetGreeting(), "Hello, Ada!"; got != want {
		t.Errorf("Greeting = %q, want %q", got, want)
	}
}

func TestGreetRejectsMissingBearerToken(t *testing.T) {
	t.Parallel()

	_, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	client := newTestClient(t, keys)

	_, err := client.Greet(context.Background(), connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"}))
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeUnauthenticated; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

func TestGreetRejectsMissingName(t *testing.T) {
	t.Parallel()

	authorization, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	client := newTestClient(t, keys)

	req := connectrpc.NewRequest(&greetv1.GreetRequest{})
	req.Header().Set("Authorization", authorization)

	_, err := client.Greet(context.Background(), req)
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeInvalidArgument; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

func TestPingAcceptsCallWithoutToken(t *testing.T) {
	t.Parallel()

	_, keys := mintInternalJWT(t, internaljwt.TokenUseTenantAccess, "greeting.read", "a1b2c3d4e5f60718")
	client := newTestClient(t, keys)

	res, err := client.Ping(context.Background(), connectrpc.NewRequest(&greetv1.PingRequest{}))
	if err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	if got, want := res.Msg.GetMessage(), "pong"; got != want {
		t.Errorf("Message = %q, want %q", got, want)
	}
}
