package httpapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
)

const (
	testIssuerID       = "service-gateway"
	testAudience       = "tolo-tenant-management"
	testSigningKeyID   = "dev-key-1"
	testPublishedKeyID = "next-key"
)

var jwkMembers = []string{"kty", "crv", "kid", "use", "alg", "x", "y"}

type staticKeyProvider struct {
	keys issuer.KeySet
}

func (p staticKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	return p.keys, nil
}

type stubJWKSSource struct {
	mu       sync.Mutex
	document internaljwt.JWKS
	err      error
}

func (s *stubJWKSSource) JWKS(context.Context) (internaljwt.JWKS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.document, s.err
}

func (s *stubJWKSSource) set(document internaljwt.JWKS, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.document, s.err = document, err
}

func newTestIssuer(t *testing.T) *issuer.Issuer {
	t.Helper()

	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	published, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	internalIssuer, err := issuer.New(testIssuerID, staticKeyProvider{
		keys: issuer.KeySet{
			Signing: issuer.SigningKey{KeyID: testSigningKeyID, Key: signing},
			Published: []issuer.PublishedKey{
				{KeyID: testPublishedKeyID, Key: &published.PublicKey},
			},
		},
	})
	if err != nil {
		t.Fatalf("issuer.New() error = %v, want nil", err)
	}

	return internalIssuer
}

func newTestJWK(t *testing.T, keyID string) internaljwt.JWK {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	jwk, err := internaljwt.NewJWK(keyID, &key.PublicKey)
	if err != nil {
		t.Fatalf("NewJWK() error = %v, want nil", err)
	}

	return jwk
}

type response struct {
	status int
	header http.Header
	body   string
}

func sendRequest(t *testing.T, handler http.Handler, req *http.Request) response {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return response{status: res.StatusCode, header: res.Header, body: string(body)}
}

func getJWKS(t *testing.T, handler http.Handler) response {
	t.Helper()

	return sendRequest(t, handler, httptest.NewRequest(http.MethodGet, httpapi.JWKSPath, nil))
}

func decodeJWKSKeys(t *testing.T, body string) []map[string]any {
	t.Helper()

	var document map[string]any

	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}

	raw, ok := document["keys"].([]any)
	if !ok {
		t.Fatalf("document = %v, want a \"keys\" array", document)
	}

	keys := make([]map[string]any, 0, len(raw))

	for _, value := range raw {
		key, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("key = %v, want an object", value)
		}

		keys = append(keys, key)
	}

	return keys
}

func TestJWKSPublishesSigningAndPublishedKeys(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewJWKSHandler(newTestIssuer(t))

	res := getJWKS(t, handler)
	if got, want := res.status, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	var document internaljwt.JWKS

	if err := json.Unmarshal([]byte(res.body), &document); err != nil {
		t.Fatalf("Unmarshal() error = %v, want nil", err)
	}

	keyIDs := make([]string, 0, len(document.Keys))
	for _, key := range document.Keys {
		keyIDs = append(keyIDs, key.KeyID)
	}

	for _, want := range []string{testSigningKeyID, testPublishedKeyID} {
		if !slices.Contains(keyIDs, want) {
			t.Errorf("kids = %v, want them to contain %q", keyIDs, want)
		}
	}
}

func TestJWKSCarriesNoPrivateKeyMaterial(t *testing.T) {
	t.Parallel()

	res := getJWKS(t, httpapi.NewJWKSHandler(newTestIssuer(t)))

	keys := decodeJWKSKeys(t, res.body)
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}

	for _, key := range keys {
		for member := range key {
			if !slices.Contains(jwkMembers, member) {
				t.Errorf("key %v holds member %q, want one of %v", key, member, jwkMembers)
			}
		}

		if _, found := key["d"]; found {
			t.Errorf("key %v holds the private component %q", key, "d")
		}
	}

	if strings.Contains(res.body, `"d"`) {
		t.Errorf("body = %q, want it to not carry a private component", res.body)
	}
}

func TestJWKSIgnoresAuthenticationHeaders(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewJWKSHandler(newTestIssuer(t))

	base := getJWKS(t, handler)

	tests := map[string]map[string]string{
		"authorization":            {"Authorization": "Bearer x"},
		"workload authorization":   {"workload-authorization": "Bearer x"},
		"serverless authorization": {"X-Serverless-Authorization": "Bearer x"},
		"dpop":                     {"DPoP": "x"},
		"every authentication header": {
			"Authorization":              "Bearer x",
			"workload-authorization":     "Bearer x",
			"X-Serverless-Authorization": "Bearer x",
			"DPoP":                       "x",
		},
	}

	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, httpapi.JWKSPath, nil)
			for key, value := range headers {
				req.Header.Set(key, value)
			}

			res := sendRequest(t, handler, req)

			if got, want := res.status, base.status; got != want {
				t.Errorf("status = %d, want %d", got, want)
			}

			if res.body != base.body {
				t.Errorf("body = %q, want %q", res.body, base.body)
			}

			for _, header := range []string{"ETag", "Cache-Control"} {
				if got, want := res.header.Get(header), base.header.Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}

			if got := res.header.Get("Vary"); got != "" {
				t.Errorf("Vary = %q, want it to be absent", got)
			}
		})
	}
}

func TestJWKSResponseHeaders(t *testing.T) {
	t.Parallel()

	res := getJWKS(t, httpapi.NewJWKSHandler(newTestIssuer(t)))

	if got, want := res.status, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	if got, want := res.header.Get("Content-Type"), "application/json"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	if got, want := res.header.Get("Cache-Control"), "public, max-age=300"; got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}

	sum := sha256.Sum256([]byte(res.body))

	want := `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
	if got := res.header.Get("ETag"); got != want {
		t.Errorf("ETag = %q, want %q", got, want)
	}

	if got := res.header.Get("Last-Modified"); got != "" {
		t.Errorf("Last-Modified = %q, want it to be absent", got)
	}
}

func TestJWKSHonoursIfNoneMatch(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewJWKSHandler(newTestIssuer(t))

	res := getJWKS(t, handler)

	etag := res.header.Get("ETag")
	if etag == "" {
		t.Fatal("ETag is empty, want an entity tag")
	}

	matching := httptest.NewRequest(http.MethodGet, httpapi.JWKSPath, nil)
	matching.Header.Set("If-None-Match", etag)

	notModified := sendRequest(t, handler, matching)

	if got, want := notModified.status, http.StatusNotModified; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	if notModified.body != "" {
		t.Errorf("body = %q, want it to be empty", notModified.body)
	}

	stale := httptest.NewRequest(http.MethodGet, httpapi.JWKSPath, nil)
	stale.Header.Set("If-None-Match", `"an-entity-tag-of-another-key-set"`)

	modified := sendRequest(t, handler, stale)

	if got, want := modified.status, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	if modified.body == "" {
		t.Error("body is empty, want the JWKS document")
	}
}

func TestJWKSHead(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewHandler(httpapi.PublicRoutes(httpapi.NewJWKSHandler(newTestIssuer(t))))

	res := sendRequest(t, handler, httptest.NewRequest(http.MethodHead, httpapi.JWKSPath, nil))

	if got, want := res.status, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	if res.body != "" {
		t.Errorf("body = %q, want it to be empty", res.body)
	}

	if res.header.Get("ETag") == "" {
		t.Error("ETag is empty, want an entity tag")
	}
}

func TestJWKSRejectsPost(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewHandler(httpapi.PublicRoutes(httpapi.NewJWKSHandler(newTestIssuer(t))))

	res := sendRequest(t, handler, httptest.NewRequest(http.MethodPost, httpapi.JWKSPath, nil))

	if got, want := res.status, http.StatusMethodNotAllowed; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestJWKSSourceFailureIsServiceUnavailable(t *testing.T) {
	t.Parallel()

	source := &stubJWKSSource{
		mu:       sync.Mutex{},
		document: internaljwt.JWKS{Keys: nil},
		err:      errors.New("the signing key file /etc/tolo/keys/signing.pem is unreadable"),
	}

	res := getJWKS(t, httpapi.NewJWKSHandler(source))

	if got, want := res.status, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	if got, want := res.body, "jwks unavailable"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	if got, want := res.header.Get("Cache-Control"), "no-store"; got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}

	for _, leak := range []string{"signing.pem", "unreadable", "/etc/tolo"} {
		if strings.Contains(res.body, leak) {
			t.Errorf("body = %q, want it to not disclose %q", res.body, leak)
		}
	}
}

func TestJWKSFollowsTheKeysOfEachRequest(t *testing.T) {
	t.Parallel()

	source := &stubJWKSSource{
		mu:       sync.Mutex{},
		document: internaljwt.JWKS{Keys: []internaljwt.JWK{newTestJWK(t, testSigningKeyID)}},
		err:      nil,
	}

	handler := httpapi.NewJWKSHandler(source)

	before := getJWKS(t, handler)

	source.set(internaljwt.JWKS{
		Keys: []internaljwt.JWK{
			newTestJWK(t, testSigningKeyID),
			newTestJWK(t, testPublishedKeyID),
		},
	}, nil)

	after := getJWKS(t, handler)

	if before.body == after.body {
		t.Errorf("body = %q for both key sets, want it to follow the keys", after.body)
	}

	if got, want := after.header.Get("ETag"), before.header.Get("ETag"); got == want {
		t.Errorf("ETag = %q for both key sets, want it to follow the body", got)
	}

	if !strings.Contains(after.body, testPublishedKeyID) {
		t.Errorf("body = %q, want it to carry the kid %q", after.body, testPublishedKeyID)
	}
}

func TestJWKSVerifiesTokensThroughTheClientCache(t *testing.T) {
	t.Parallel()

	internalIssuer := newTestIssuer(t)

	server := httptest.NewServer(httpapi.NewHandler(
		httpapi.PublicRoutes(httpapi.NewJWKSHandler(internalIssuer)),
	))
	t.Cleanup(server.Close)

	cache, err := jwks.New(jwks.Config{
		URL:             server.URL + httpapi.JWKSPath,
		HTTPClient:      server.Client(),
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    0,
		RetryBackoff:    nil,
		MaxDocumentSize: 0,
	})
	if err != nil {
		t.Fatalf("jwks.New() error = %v, want nil", err)
	}

	tokenVerifier, err := verifier.New(testIssuerID, testAudience, cache)
	if err != nil {
		t.Fatalf("verifier.New() error = %v, want nil", err)
	}

	ctx := t.Context()

	issued, err := internalIssuer.IssueFromExternal(ctx, issuer.ExternalTokenInput{
		Audience:        testAudience,
		TokenUse:        internaljwt.TokenUseTenantAccess,
		Subject:         "user-1",
		ClientID:        "admin-ui",
		Scope:           "tenant.write events.read",
		SourceJTI:       "external-jti-1",
		SourceExpiresAt: time.Now().Add(15 * time.Minute),
		TenantPublicID:  "0123456789abcdef",
		EventPublicID:   "",
	})
	if err != nil {
		t.Fatalf("IssueFromExternal() error = %v, want nil", err)
	}

	claims, err := tokenVerifier.Verify(ctx, issued.Token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if claims.Subject != "user-1" {
		t.Errorf("sub = %q, want %q", claims.Subject, "user-1")
	}
}
