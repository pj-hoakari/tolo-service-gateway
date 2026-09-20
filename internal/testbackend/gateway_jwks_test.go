package testbackend_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/jwtgen"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/testbackend"
)

const (
	gatewayIssuerID      = "service-gateway"
	gatewaySigningKeyID  = "dev-key-1"
	backendAudience      = "tolo-testbackend"
	otherServiceAudience = "tolo-tenant-management"
	foreignKeyID         = "a-key-the-gateway-does-not-publish"
)

const (
	greetScope         = "greeting.read"
	greetTenantID      = "a1b2c3d4e5f60718"
	greetSubject       = "user-1"
	greetClientID      = "admin-ui"
	greetSourceJTI     = "external-jti-1"
	greetSourceTimeout = 15 * time.Minute
	jwksFetchTimeout   = 2 * time.Second
)

type gatewayKeyProvider struct {
	keys issuer.KeySet
}

func (p gatewayKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	return p.keys, nil
}

func newGatewayIssuer(t *testing.T) *issuer.Issuer {
	t.Helper()

	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	gatewayIssuer, err := issuer.New(gatewayIssuerID, gatewayKeyProvider{
		keys: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: gatewaySigningKeyID, Key: signing},
			Published: nil,
		},
	})
	if err != nil {
		t.Fatalf("issuer.New() error = %v, want nil", err)
	}

	return gatewayIssuer
}

func newGatewayServer(t *testing.T, gatewayIssuer *issuer.Issuer) *httptest.Server {
	t.Helper()

	gateway := httptest.NewServer(httpapi.NewHandler(
		httpapi.PublicRoutes(httpapi.NewJWKSHandler(gatewayIssuer)),
	))
	t.Cleanup(gateway.Close)

	return gateway
}

func newGateway(t *testing.T) (*issuer.Issuer, string) {
	t.Helper()

	gatewayIssuer := newGatewayIssuer(t)

	return gatewayIssuer, newGatewayServer(t, gatewayIssuer).URL + httpapi.JWKSPath
}

func newBackendClient(t *testing.T, jwksURL string) greetv1connect.GreetServiceClient {
	t.Helper()

	cache, err := jwks.New(jwks.Config{
		URL:             jwksURL,
		HTTPClient:      nil,
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    jwksFetchTimeout,
		RetryBackoff:    []time.Duration{},
		MaxDocumentSize: 0,
	})
	if err != nil {
		t.Fatalf("jwks.New() error = %v, want nil", err)
	}

	tokenVerifier, err := verifier.New(gatewayIssuerID, backendAudience, cache)
	if err != nil {
		t.Fatalf("verifier.New() error = %v, want nil", err)
	}

	handler, err := testbackend.NewHandler(tokenVerifier)
	if err != nil {
		t.Fatalf("NewHandler() error = %v, want nil", err)
	}

	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)

	return greetv1connect.NewGreetServiceClient(backend.Client(), backend.URL)
}

func issueGatewayToken(t *testing.T, gatewayIssuer *issuer.Issuer, audience string) string {
	t.Helper()

	issued, err := gatewayIssuer.IssueFromExternal(t.Context(), issuer.ExternalTokenInput{
		Audience:        audience,
		TokenUse:        internaljwt.TokenUseTenantAccess,
		Subject:         greetSubject,
		ClientID:        greetClientID,
		Scope:           greetScope,
		SourceJTI:       greetSourceJTI,
		SourceExpiresAt: time.Now().Add(greetSourceTimeout),
		TenantPublicID:  greetTenantID,
		EventPublicID:   "",
	})
	if err != nil {
		t.Fatalf("IssueFromExternal() error = %v, want nil", err)
	}

	return issued.Token
}

func issueForeignToken(t *testing.T) string {
	t.Helper()

	output, err := jwtgen.Generate(jwtgen.Config{
		Issuer:         gatewayIssuerID,
		Audience:       backendAudience,
		TokenUse:       internaljwt.TokenUseTenantAccess,
		TenantPublicID: greetTenantID,
		Scope:          greetScope,
		KeyID:          foreignKeyID,
		TTL:            time.Hour,
	})
	if err != nil {
		t.Fatalf("jwtgen.Generate() error = %v, want nil", err)
	}

	return output.Token
}

func TestBackendVerifiesGatewayTokensThroughItsJWKS(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		token        func(t *testing.T, gatewayIssuer *issuer.Issuer) string
		wantGreeting string
		wantCode     connectrpc.Code
	}{
		"a token the gateway issued for this backend is accepted": {
			token: func(t *testing.T, gatewayIssuer *issuer.Issuer) string {
				t.Helper()

				return issueGatewayToken(t, gatewayIssuer, backendAudience)
			},
			wantGreeting: "Hello, Ada!",
			wantCode:     0,
		},
		"a token the gateway issued for another service is rejected": {
			token: func(t *testing.T, gatewayIssuer *issuer.Issuer) string {
				t.Helper()

				return issueGatewayToken(t, gatewayIssuer, otherServiceAudience)
			},
			wantGreeting: "",
			wantCode:     connectrpc.CodeUnauthenticated,
		},
		"a token signed by a key the gateway JWKS does not carry is rejected": {
			token: func(t *testing.T, _ *issuer.Issuer) string {
				t.Helper()

				return issueForeignToken(t)
			},
			wantGreeting: "",
			wantCode:     connectrpc.CodeUnauthenticated,
		},
		"a request without a token is rejected": {
			token:        nil,
			wantGreeting: "",
			wantCode:     connectrpc.CodeUnauthenticated,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gatewayIssuer, jwksURL := newGateway(t)
			client := newBackendClient(t, jwksURL)

			req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
			if tt.token != nil {
				req.Header().Set("Authorization", "Bearer "+tt.token(t, gatewayIssuer))
			}

			res, err := client.Greet(t.Context(), req)

			if tt.wantCode != 0 {
				if got := connectrpc.CodeOf(err); got != tt.wantCode {
					t.Fatalf("Greet() error code = %v, want %v", got, tt.wantCode)
				}

				return
			}

			if err != nil {
				t.Fatalf("Greet() error = %v, want nil", err)
			}

			if got := res.Msg.GetGreeting(); got != tt.wantGreeting {
				t.Errorf("Greeting = %q, want %q", got, tt.wantGreeting)
			}
		})
	}
}

func TestBackendReportsUnavailableWhenTheGatewayJWKSCannotBeFetched(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		jwksURL func(t *testing.T, gatewayIssuer *issuer.Issuer) string
	}{
		"the gateway is stopped": {
			jwksURL: func(t *testing.T, gatewayIssuer *issuer.Issuer) string {
				t.Helper()

				gateway := newGatewayServer(t, gatewayIssuer)
				jwksURL := gateway.URL + httpapi.JWKSPath
				gateway.Close()

				return jwksURL
			},
		},
		"the gateway JWKS fails": {
			jwksURL: func(t *testing.T, _ *issuer.Issuer) string {
				t.Helper()

				gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
				t.Cleanup(gateway.Close)

				return gateway.URL + httpapi.JWKSPath
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gatewayIssuer := newGatewayIssuer(t)
			client := newBackendClient(t, tt.jwksURL(t, gatewayIssuer))

			req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"})
			req.Header().Set("Authorization", "Bearer "+issueGatewayToken(t, gatewayIssuer, backendAudience))

			_, err := client.Greet(t.Context(), req)
			if got, want := connectrpc.CodeOf(err), connectrpc.CodeUnavailable; got != want {
				t.Fatalf("Greet() error code = %v, want %v (error = %v)", got, want, err)
			}
		})
	}
}
