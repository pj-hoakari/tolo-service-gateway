package fakeidp_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
	"github.com/pj-hoakari/tolo-service-gateway/internal/fakeidp"
)

const (
	testAudience = "backend-api"
	testTenantID = "0123456789abcdef"
	testScope    = "greeting.read"
	testSubject  = "user-1"
	testClientID = "admin-ui"
)

func startFakeIDP(t *testing.T) string {
	t.Helper()

	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)

	handler, err := fakeidp.NewHandler(fakeidp.Config{
		Issuer:   "http://" + server.Listener.Addr().String(),
		Audience: testAudience,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v, want nil", err)
	}

	server.Config.Handler = handler
	server.Start()

	return server.URL
}

func get(t *testing.T, target, host string) map[string]any {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	if host != "" {
		req.Host = host
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", target, res.StatusCode, http.StatusOK)
	}

	var body map[string]any

	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	return body
}

func issueToken(t *testing.T, issuer string, request map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+fakeidp.TokenPath, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("POST %s status = %d, want %d (body = %q)", fakeidp.TokenPath, res.StatusCode, http.StatusOK, body)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	if body.AccessToken == "" {
		t.Fatal("access_token is empty, want a signed token")
	}

	return body.AccessToken
}

func TestHandlerServesTheDiscoveryDocuments(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDP(t)

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		document := get(t, issuer+path, "")

		want := map[string]any{
			"issuer":                 issuer,
			"jwks_uri":               issuer + fakeidp.JWKSPath,
			"introspection_endpoint": issuer + fakeidp.IntrospectionPath,
		}

		for key, value := range want {
			if got := document[key]; got != value {
				t.Errorf("GET %s %s = %#v, want %#v", path, key, got, value)
			}
		}
	}
}

func TestHandlerKeepsTheIssuerOutOfTheHostHeader(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDP(t)

	document := get(t, issuer+"/.well-known/openid-configuration", "idp.example.com")

	if got := document["issuer"]; got != issuer {
		t.Errorf("issuer = %#v, want %q", got, issuer)
	}
}

func TestHandlerServesAJWKSWithOneSigningKey(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDP(t)

	document := get(t, issuer+fakeidp.JWKSPath, "")

	keys, ok := document["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("keys = %#v, want one key", document["keys"])
	}

	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("keys[0] = %#v, want an object", keys[0])
	}

	for member, want := range map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256"} {
		if got := key[member]; got != want {
			t.Errorf("keys[0].%s = %#v, want %#v", member, got, want)
		}
	}

	if got, ok := key["kid"].(string); !ok || got == "" {
		t.Errorf("keys[0].kid = %#v, want a non-empty string", key["kid"])
	}
}

func TestHandlerIssuesTokensTheVerifierAccepts(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDP(t)

	token := issueToken(t, issuer, map[string]any{
		"token_use":   "tenant_access",
		"sub":         testSubject,
		"client_id":   testClientID,
		"scope":       testScope,
		"tenant_id":   testTenantID,
		"ttl_seconds": 300,
	})

	claims := verifyToken(t, issuer, token)

	for name, got := range map[string]string{
		"Subject":  claims.Subject,
		"ClientID": claims.ClientID,
		"TokenUse": claims.TokenUse,
		"Scope":    claims.Scope,
		"TenantID": claims.TenantID,
	} {
		want := map[string]string{
			"Subject":  testSubject,
			"ClientID": testClientID,
			"TokenUse": "tenant_access",
			"Scope":    testScope,
			"TenantID": testTenantID,
		}[name]

		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	if claims.JTI == "" {
		t.Error("JTI is empty, want the identifier of the issued token")
	}

	if claims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is zero, want the expiry of the issued token")
	}
}

func verifyToken(t *testing.T, issuer, token string) externaltoken.Claims {
	t.Helper()

	metadata, err := externaltoken.Discover(t.Context(), nil, issuer)
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	keys, err := externaltoken.NewKeySet(externaltoken.KeySetConfig{URL: metadata.JWKSURI})
	if err != nil {
		t.Fatalf("NewKeySet() error = %v, want nil", err)
	}

	verifier, err := externaltoken.NewVerifier(externaltoken.Config{
		Issuer:   issuer,
		Audience: testAudience,
		Keys:     keys,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	claims, err := verifier.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	return claims
}
