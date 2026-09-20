package fakeidp_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func startFakeIDPWith(t *testing.T, clientID, secret string) string {
	t.Helper()

	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)

	handler, err := fakeidp.NewHandler(fakeidp.Config{
		Issuer:                    "http://" + server.Listener.Addr().String(),
		Audience:                  testAudience,
		IntrospectionClientID:     clientID,
		IntrospectionClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v, want nil", err)
	}

	server.Config.Handler = handler
	server.Start()

	return server.URL
}

func startFakeIDP(t *testing.T) string {
	t.Helper()

	return startFakeIDPWith(t, "", "")
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

const (
	testIntrospectionClientID   = "gateway-introspection"
	testIntrospectionCredential = "introspection-client-credential"
)

func introspect(t *testing.T, issuer, clientID, secret, token string) (int, map[string]any) {
	t.Helper()

	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+fakeidp.IntrospectionPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if clientID != "" || secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return res.StatusCode, nil
	}

	var body map[string]any

	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	return res.StatusCode, body
}

func revoke(t *testing.T, issuer string, request map[string]any) int {
	t.Helper()

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+fakeidp.RevokePath, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	return res.StatusCode
}

func tokenRequest() map[string]any {
	return map[string]any{
		"token_use":   "tenant_access",
		"sub":         testSubject,
		"client_id":   testClientID,
		"scope":       testScope,
		"tenant_id":   testTenantID,
		"ttl_seconds": 300,
	}
}

func TestHandlerReportsAnIssuedTokenAsActive(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDPWith(t, testIntrospectionClientID, testIntrospectionCredential)
	token := issueToken(t, issuer, tokenRequest())

	status, body := introspect(t, issuer, testIntrospectionClientID, testIntrospectionCredential, token)
	if status != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d", fakeidp.IntrospectionPath, status, http.StatusOK)
	}

	if got := body["active"]; got != true {
		t.Fatalf("active = %#v, want true", got)
	}

	for member, want := range map[string]any{
		"sub":       testSubject,
		"client_id": testClientID,
		"scope":     testScope,
		"token_use": "tenant_access",
	} {
		if got := body[member]; got != want {
			t.Errorf("%s = %#v, want %#v", member, got, want)
		}
	}

	if got, named := body["jti"].(string); !named || got == "" {
		t.Errorf("jti = %#v, want the identifier of the token", body["jti"])
	}
}

func TestHandlerReportsARevokedTokenAsInactive(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, issuer, token, jti string) map[string]any{
		"by token": func(_ *testing.T, _, token, _ string) map[string]any {
			return map[string]any{"token": token}
		},
		"by jti": func(_ *testing.T, _, _, jti string) map[string]any {
			return map[string]any{"jti": jti}
		},
	}

	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			issuer := startFakeIDPWith(t, testIntrospectionClientID, testIntrospectionCredential)
			token := issueToken(t, issuer, tokenRequest())

			_, body := introspect(t, issuer, testIntrospectionClientID, testIntrospectionCredential, token)

			jti, named := body["jti"].(string)
			if !named {
				t.Fatalf("jti = %#v, want the identifier of the token", body["jti"])
			}

			if status := revoke(t, issuer, request(t, issuer, token, jti)); status != http.StatusOK {
				t.Fatalf("POST %s status = %d, want %d", fakeidp.RevokePath, status, http.StatusOK)
			}

			_, revoked := introspect(t, issuer, testIntrospectionClientID, testIntrospectionCredential, token)

			if got := revoked["active"]; got != false {
				t.Errorf("active = %#v, want false once the token is revoked", got)
			}
		})
	}
}

func TestHandlerReportsAnUnknownTokenAsInactive(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDPWith(t, testIntrospectionClientID, testIntrospectionCredential)
	other := issueToken(t, startFakeIDPWith(t, testIntrospectionClientID, testIntrospectionCredential), tokenRequest())

	for name, token := range map[string]string{
		"a token another IdP issued": other,
		"a value that is not a JWT":  "not-a-jwt",
		"an empty token":             "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, body := introspect(t, issuer, testIntrospectionClientID, testIntrospectionCredential, token)

			if got := body["active"]; got != false {
				t.Errorf("active = %#v, want false", got)
			}
		})
	}
}

func TestHandlerRefusesIntrospectionByAnUnknownClient(t *testing.T) {
	t.Parallel()

	configured := startFakeIDPWith(t, testIntrospectionClientID, testIntrospectionCredential)
	token := issueToken(t, configured, tokenRequest())

	tests := map[string]struct {
		issuer   string
		clientID string
		secret   string
	}{
		"without credentials": {
			issuer:   configured,
			clientID: "",
			secret:   "",
		},
		"with another client ID": {
			issuer:   configured,
			clientID: "another-client",
			secret:   testIntrospectionCredential,
		},
		"with another secret": {
			issuer:   configured,
			clientID: testIntrospectionClientID,
			secret:   "another-credential",
		},
		"against an IdP without an introspection client": {
			issuer:   startFakeIDP(t),
			clientID: testIntrospectionClientID,
			secret:   testIntrospectionCredential,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			status, _ := introspect(t, test.issuer, test.clientID, test.secret, token)
			if status != http.StatusUnauthorized {
				t.Errorf("POST %s status = %d, want %d", fakeidp.IntrospectionPath, status, http.StatusUnauthorized)
			}
		})
	}
}

func TestHandlerRefusesARevocationItCannotResolve(t *testing.T) {
	t.Parallel()

	issuer := startFakeIDPWith(t, testIntrospectionClientID, testIntrospectionCredential)

	if status := revoke(t, issuer, map[string]any{"token": "not-a-jwt"}); status != http.StatusBadRequest {
		t.Errorf("POST %s status = %d, want %d", fakeidp.RevokePath, status, http.StatusBadRequest)
	}
}

func TestNewHandlerRejectsHalfAnIntrospectionClient(t *testing.T) {
	t.Parallel()

	tests := map[string]fakeidp.Config{
		"without the secret":    {Issuer: "http://idp.example.com", Audience: testAudience, IntrospectionClientID: testIntrospectionClientID},
		"without the client ID": {Issuer: "http://idp.example.com", Audience: testAudience, IntrospectionClientSecret: testIntrospectionCredential},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := fakeidp.NewHandler(config); !errors.Is(err, fakeidp.ErrInvalidConfig) {
				t.Errorf("NewHandler() error = %v, want %v", err, fakeidp.ErrInvalidConfig)
			}
		})
	}
}
