package idp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
	"github.com/pj-hoakari/tolo-service-gateway/internal/idp"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
)

const (
	testAudience = "backend-api"
	testTenantID = "0123456789abcdef"
	testEventID  = "fedcba9876543210"
	testKeyID    = "stub-idp-1"
	testSubject  = "user-1"
	testClientID = "admin-ui"
	testScope    = "greeting.read tenant.read"

	testIntrospectionClientID   = "gateway-introspection"
	testIntrospectionCredential = "introspection-client-credential"
)

const retryDelay = 5 * time.Millisecond

var signingKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return key
})

type stubIDP struct {
	issuer            string
	declaredIssuer    atomic.Value
	metadataStatus    atomic.Int64
	jwksStatus        atomic.Int64
	introspectStatus  atomic.Int64
	omitIntrospection atomic.Bool
	inactive          atomic.Bool
	introspections    atomic.Int64
}

func newStubIDP(t *testing.T) *stubIDP {
	t.Helper()

	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)

	stub := &stubIDP{issuer: "http://" + server.Listener.Addr().String()}
	stub.declaredIssuer.Store(stub.issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", stub.handleMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", stub.handleMetadata)
	mux.HandleFunc("GET /jwks", stub.handleJWKS)
	mux.HandleFunc("POST /introspect", stub.handleIntrospect)

	server.Config.Handler = mux
	server.Start()

	return stub
}

func (s *stubIDP) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	if status := s.metadataStatus.Load(); status != 0 {
		w.WriteHeader(int(status))

		return
	}

	declared, _ := s.declaredIssuer.Load().(string)

	document := map[string]any{
		"issuer":   declared,
		"jwks_uri": s.issuer + "/jwks",
	}

	if !s.omitIntrospection.Load() {
		document["introspection_endpoint"] = s.issuer + "/introspect"
	}

	writeJSON(w, document)
}

func (s *stubIDP) handleIntrospect(w http.ResponseWriter, _ *http.Request) {
	s.introspections.Add(1)

	if status := s.introspectStatus.Load(); status != 0 {
		w.WriteHeader(int(status))

		return
	}

	writeJSON(w, map[string]any{"active": !s.inactive.Load()})
}

func (s *stubIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	if status := s.jwksStatus.Load(); status != 0 {
		w.WriteHeader(int(status))

		return
	}

	public := signingKey().PublicKey

	writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"kid": testKeyID,
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
}

func writeJSON(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

func (s *stubIDP) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKeyID

	signed, err := token.SignedString(signingKey())
	if err != nil {
		t.Fatalf("SignedString() error = %v, want nil", err)
	}

	return signed
}

func (s *stubIDP) claims() jwt.MapClaims {
	now := time.Now()

	return jwt.MapClaims{
		"iss":       s.issuer,
		"aud":       testAudience,
		"sub":       testSubject,
		"client_id": testClientID,
		"token_use": "tenant_access",
		"scope":     testScope,
		"tenant_id": testTenantID,
		"jti":       "external-jti-1",
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	}
}

func newProvider(t *testing.T, stub *stubIDP) *idp.Provider {
	t.Helper()

	provider, err := idp.New(idp.Config{
		Issuer:     stub.issuer,
		Audience:   testAudience,
		RetryDelay: retryDelay,
	})
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	return provider
}

func runProvider(t *testing.T, stub *stubIDP) *idp.Provider {
	t.Helper()

	provider := newProvider(t, stub)

	if err := provider.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	return provider
}

func runLegacyScopeProvider(t *testing.T, stub *stubIDP) *idp.Provider {
	t.Helper()

	provider, err := idp.New(idp.Config{
		Issuer:                 stub.issuer,
		Audience:               testAudience,
		RetryDelay:             retryDelay,
		LegacyEventsWriteScope: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	if err := provider.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	return provider
}

func verifiedScope(t *testing.T, provider *idp.Provider, stub *stubIDP, scope string) string {
	t.Helper()

	claims := stub.claims()
	claims["scope"] = scope

	verified, err := provider.Verify(t.Context(), stub.sign(t, claims))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	return verified.Scope
}

func TestProviderKeepsTheLegacyScopeWhenTheRewriteIsDisabled(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := runProvider(t, stub)

	if got, want := verifiedScope(t, provider, stub, "tenant.read events.write"), "tenant.read events.write"; got != want {
		t.Errorf("Scope = %q, want %q", got, want)
	}
}

func TestProviderRewritesTheLegacyEventsWriteScope(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := runLegacyScopeProvider(t, stub)

	tests := map[string]struct {
		scope string
		want  string
	}{
		"the legacy scope alone": {
			scope: "events.write",
			want:  "events.manage events.operate events.report",
		},
		"among other scopes": {
			scope: "tenant.read events.write events.read",
			want:  "tenant.read events.manage events.operate events.report events.read",
		},
		"beside a scope it expands to": {
			scope: "events.write events.manage",
			want:  "events.manage events.operate events.report",
		},
		"a scope without the legacy value": {
			scope: "tenant.read  events.read",
			want:  "tenant.read  events.read",
		},
		"a scope the legacy value is a prefix of": {
			scope: "events.writeX",
			want:  "events.writeX",
		},
		"a scope the legacy value is a suffix of": {
			scope: "xevents.write",
			want:  "xevents.write",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := verifiedScope(t, provider, stub, tt.scope); got != tt.want {
				t.Errorf("Scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func newIntrospectingProvider(t *testing.T, stub *stubIDP) *idp.Provider {
	t.Helper()

	provider, err := idp.New(idp.Config{
		Issuer:                    stub.issuer,
		Audience:                  testAudience,
		RetryDelay:                retryDelay,
		IntrospectionClientID:     testIntrospectionClientID,
		IntrospectionClientSecret: testIntrospectionCredential,
	})
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	return provider
}

func verifiedToken() authn.ExternalToken {
	return authn.ExternalToken{
		Subject:   testSubject,
		JTI:       "external-jti-1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func TestProviderAsksTheIDPWhetherTheTokenIsActive(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := newIntrospectingProvider(t, stub)

	if err := provider.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	active, err := provider.Active(t.Context(), stub.sign(t, stub.claims()), verifiedToken())
	if err != nil {
		t.Fatalf("Active() error = %v, want nil", err)
	}

	if !active {
		t.Error("Active() = false, want true for a token the IdP reports as active")
	}

	if got := stub.introspections.Load(); got != 1 {
		t.Errorf("introspection requests = %d, want 1", got)
	}
}

func TestProviderReportsAnIntrospectionItCannotMake(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, stub *stubIDP) *idp.Provider{
		"before the metadata is resolved": func(t *testing.T, stub *stubIDP) *idp.Provider {
			t.Helper()

			return newIntrospectingProvider(t, stub)
		},
		"without introspection configured": func(t *testing.T, stub *stubIDP) *idp.Provider {
			t.Helper()

			return runProvider(t, stub)
		},
		"with an endpoint that fails": func(t *testing.T, stub *stubIDP) *idp.Provider {
			t.Helper()

			provider := newIntrospectingProvider(t, stub)

			if err := provider.Run(t.Context()); err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}

			stub.introspectStatus.Store(http.StatusServiceUnavailable)

			return provider
		},
	}

	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			stub := newStubIDP(t)
			provider := build(t, stub)

			active, err := provider.Active(t.Context(), stub.sign(t, stub.claims()), verifiedToken())
			if !errors.Is(err, externaltoken.ErrIntrospectionUnavailable) {
				t.Fatalf("Active() error = %v, want %v", err, externaltoken.ErrIntrospectionUnavailable)
			}

			if active {
				t.Error("Active() = true, want false when the IdP cannot be asked")
			}
		})
	}
}

func TestRunStopsWhenTheIDPHasNoIntrospectionEndpoint(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	stub.omitIntrospection.Store(true)

	if err := newIntrospectingProvider(t, stub).Run(t.Context()); !errors.Is(err, idp.ErrInvalidConfig) {
		t.Errorf("Run() error = %v, want %v", err, idp.ErrInvalidConfig)
	}
}

func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]idp.Config{
		"without an issuer":    {Audience: testAudience},
		"without an audience":  {Issuer: "https://idp.example.com"},
		"without either value": {},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := idp.New(config); !errors.Is(err, idp.ErrInvalidConfig) {
				t.Errorf("New() error = %v, want %v", err, idp.ErrInvalidConfig)
			}
		})
	}
}

func TestProviderIsUnavailableBeforeTheMetadataIsResolved(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := newProvider(t, stub)

	if err := provider.Ready(t.Context()); err == nil {
		t.Error("Ready() error = nil, want the provider to report it is not resolved yet")
	}

	if _, resolved := provider.Metadata(); resolved {
		t.Error("Metadata() reports the metadata as resolved, want it unresolved")
	}

	_, err := provider.Verify(t.Context(), stub.sign(t, stub.claims()))
	if !errors.Is(err, authn.ErrVerifierUnavailable) {
		t.Errorf("Verify() error = %v, want %v", err, authn.ErrVerifierUnavailable)
	}
}

func TestProviderVerifiesATokenOfTheSpecifiedShape(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := runProvider(t, stub)

	if err := provider.Ready(t.Context()); err != nil {
		t.Errorf("Ready() error = %v, want nil", err)
	}

	metadata, resolved := provider.Metadata()
	if !resolved {
		t.Fatal("Metadata() reports the metadata as unresolved, want it resolved")
	}

	if got, want := metadata.IntrospectionEndpoint, stub.issuer+"/introspect"; got != want {
		t.Errorf("IntrospectionEndpoint = %q, want %q", got, want)
	}

	claims := stub.claims()
	claims["token_use"] = "event_access"
	claims["event_id"] = testEventID

	verified, err := provider.Verify(t.Context(), stub.sign(t, claims))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	want := authn.ExternalToken{
		Subject:           testSubject,
		ClientID:          testClientID,
		TokenUse:          "event_access",
		Scope:             testScope,
		JTI:               "external-jti-1",
		TenantID:          testTenantID,
		EventID:           testEventID,
		ExpiresAt:         verified.ExpiresAt,
		SenderConstrained: false,
	}

	if verified != want {
		t.Errorf("Verify() = %+v, want %+v", verified, want)
	}

	if verified.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero, want the expiry of the token")
	}
}

func TestProviderReportsASenderConstrainedToken(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := runProvider(t, stub)

	claims := stub.claims()
	claims["cnf"] = map[string]any{"jkt": "jkt-thumbprint-1"}

	verified, err := provider.Verify(t.Context(), stub.sign(t, claims))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if !verified.SenderConstrained {
		t.Error("SenderConstrained = false, want true for a token with cnf")
	}
}

func TestProviderRejectsAnInvalidTokenWithoutReportingItUnavailable(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := runProvider(t, stub)

	expired := stub.claims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	otherIssuer := stub.claims()
	otherIssuer["iss"] = "https://other.example.com"

	otherAudience := stub.claims()
	otherAudience["aud"] = "other-api"

	otherTenant := stub.claims()
	otherTenant["tenant_id"] = "tenant-a"

	tests := map[string]string{
		"an expired token":             stub.sign(t, expired),
		"another issuer":               stub.sign(t, otherIssuer),
		"another audience":             stub.sign(t, otherAudience),
		"a tenant ID of another shape": stub.sign(t, otherTenant),
		"a token that is not a JWT":    "not-a-jwt",
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := provider.Verify(t.Context(), token)
			if err == nil {
				t.Fatal("Verify() error = nil, want the token rejected")
			}

			if errors.Is(err, authn.ErrVerifierUnavailable) {
				t.Errorf("Verify() error = %v, want it not to report the verifier as unavailable", err)
			}
		})
	}
}

func TestProviderReportsAnUnreachableJWKSAsUnavailable(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	provider := runProvider(t, stub)

	stub.jwksStatus.Store(http.StatusServiceUnavailable)

	_, err := provider.Verify(t.Context(), stub.sign(t, stub.claims()))
	if !errors.Is(err, authn.ErrVerifierUnavailable) {
		t.Errorf("Verify() error = %v, want %v", err, authn.ErrVerifierUnavailable)
	}
}

func TestRunRetriesUntilTheIDPAnswers(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	stub.metadataStatus.Store(http.StatusServiceUnavailable)

	provider := newProvider(t, stub)

	go func() {
		time.Sleep(4 * retryDelay)
		stub.metadataStatus.Store(0)
	}()

	if err := provider.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if err := provider.Ready(t.Context()); err != nil {
		t.Errorf("Ready() error = %v, want nil", err)
	}
}

func TestRunStopsOnMetadataItCannotUse(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	stub.declaredIssuer.Store("https://other.example.com")

	err := newProvider(t, stub).Run(t.Context())

	if !errors.Is(err, externaltoken.ErrInvalidMetadata) {
		t.Errorf("Run() error = %v, want %v", err, externaltoken.ErrInvalidMetadata)
	}
}

func TestRunStopsWhenTheContextIsCancelled(t *testing.T) {
	t.Parallel()

	stub := newStubIDP(t)
	stub.metadataStatus.Store(http.StatusServiceUnavailable)

	ctx, cancel := context.WithCancel(t.Context())

	go func() {
		time.Sleep(4 * retryDelay)
		cancel()
	}()

	if err := newProvider(t, stub).Run(ctx); err != nil {
		t.Errorf("Run() error = %v, want nil on a cancelled context", err)
	}

	cancel()
}
