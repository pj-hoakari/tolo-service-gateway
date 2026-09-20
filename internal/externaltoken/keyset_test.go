package externaltoken_test

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
)

type jwksServer struct {
	mu       sync.Mutex
	document []byte
	status   int
	delay    time.Duration
	requests int

	server *httptest.Server
}

func newJWKSServer(t *testing.T, document []byte) *jwksServer {
	t.Helper()

	keys := &jwksServer{
		document: document,
		status:   http.StatusOK,
		delay:    0,
		requests: 0,
		server:   nil,
	}

	keys.server = httptest.NewServer(http.HandlerFunc(keys.serve))
	t.Cleanup(keys.server.Close)

	return keys
}

func (s *jwksServer) serve(writer http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.requests++
	document, status, delay := s.document, s.status, s.delay
	s.mu.Unlock()

	time.Sleep(delay)

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(document)
}

func (s *jwksServer) serveDocument(document []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.document, s.status = document, status
}

func (s *jwksServer) setDelay(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delay = delay
}

func (s *jwksServer) fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.requests
}

func newKeySet(t *testing.T, keys *jwksServer, clock *testClock) *externaltoken.KeySet {
	t.Helper()

	keySet, err := externaltoken.NewKeySet(externaltoken.KeySetConfig{
		URL:             keys.server.URL,
		HTTPClient:      keys.server.Client(),
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    0,
		MaxDocumentSize: 0,
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatalf("NewKeySet() error = %v, want nil", err)
	}

	return keySet
}

func mustKey(t *testing.T, keySet *externaltoken.KeySet, keyID string) crypto.PublicKey {
	t.Helper()

	key, err := keySet.Key(t.Context(), keyID)
	if err != nil {
		t.Fatalf("Key(%q) error = %v, want nil", keyID, err)
	}

	return key
}

func TestKeySetServesTheCachedDocument(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	clock := newTestClock()
	keySet := newKeySet(t, keys, clock)

	first := mustKey(t, keySet, testRSAKeyID)

	clock.advance(externaltoken.DefaultCacheTTL - time.Second)

	second := mustKey(t, keySet, testRSAKeyID)

	if first != second {
		t.Errorf("Key() returned two different keys, want the cached one")
	}

	if got := keys.fetches(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}

	clock.advance(2 * time.Second)
	mustKey(t, keySet, testRSAKeyID)

	if got := keys.fetches(); got != 2 {
		t.Errorf("fetches after the TTL = %d, want 2", got)
	}
}

func TestKeySetRefetchesForAnUnknownKeyID(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	clock := newTestClock()
	keySet := newKeySet(t, keys, clock)

	mustKey(t, keySet, testRSAKeyID)
	keys.serveDocument(jwksDocument(t,
		rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey),
		ecJWK(testECKeyID, &signingECKey().PublicKey),
	), http.StatusOK)

	if _, err := keySet.Key(t.Context(), testECKeyID); !errors.Is(err, externaltoken.ErrUnknownKeyID) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrUnknownKeyID)
	}

	if got := keys.fetches(); got != 1 {
		t.Errorf("fetches during the refresh cooldown = %d, want 1", got)
	}

	clock.advance(externaltoken.DefaultRefreshCooldown)
	mustKey(t, keySet, testECKeyID)

	if got := keys.fetches(); got != 2 {
		t.Errorf("fetches after the refresh cooldown = %d, want 2", got)
	}
}

func TestKeySetCoalescesConcurrentFetches(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	keys.setDelay(100 * time.Millisecond)

	clock := newTestClock()
	keySet := newKeySet(t, keys, clock)

	var waiting sync.WaitGroup

	for range 8 {
		waiting.Add(1)

		go func() {
			defer waiting.Done()

			if _, err := keySet.Key(t.Context(), testRSAKeyID); err != nil {
				t.Errorf("Key() error = %v, want nil", err)
			}
		}()
	}

	waiting.Wait()

	if got := keys.fetches(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

func TestKeySetKeepsUnexpiredKeysWhenTheFetchFails(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	clock := newTestClock()
	keySet := newKeySet(t, keys, clock)

	mustKey(t, keySet, testRSAKeyID)
	keys.serveDocument(nil, http.StatusInternalServerError)
	clock.advance(externaltoken.DefaultRefreshCooldown)

	if _, err := keySet.Key(t.Context(), testECKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	mustKey(t, keySet, testRSAKeyID)

	if _, err := keySet.Key(t.Context(), testECKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() during the failure cooldown error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	if got := keys.fetches(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}

	clock.advance(externaltoken.DefaultCacheTTL)

	if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() after the cache expired error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}
}

func TestKeySetSelectsUsableKeys(t *testing.T) {
	t.Parallel()

	document := jwksDocument(t,
		rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey),
		rsaJWK(testWeakKeyID, &weakRSAKey().PublicKey),
		encryptionJWK(testEncKeyID),
		privateRSAJWK(t, "idp-private-1"),
		map[string]any{"kty": "oct", "kid": "symmetric"},
	)

	keys := newJWKSServer(t, document)
	clock := newTestClock()
	keySet := newKeySet(t, keys, clock)

	key, ok := mustKey(t, keySet, testRSAKeyID).(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Key() type = %T, want *rsa.PublicKey", key)
	}

	if _, ok := mustKey(t, keySet, "idp-private-1").(*rsa.PublicKey); !ok {
		t.Errorf("Key() did not return a public key for a JWK carrying private members")
	}

	for _, keyID := range []string{testWeakKeyID, testEncKeyID, "symmetric"} {
		if _, err := keySet.Key(t.Context(), keyID); !errors.Is(err, externaltoken.ErrUnknownKeyID) {
			t.Errorf("Key(%q) error = %v, want %v", keyID, err, externaltoken.ErrUnknownKeyID)
		}
	}
}

func privateRSAJWK(t *testing.T, keyID string) map[string]any {
	t.Helper()

	private := generateRSAKey(2048)
	value := rsaJWK(keyID, &private.PublicKey)
	value["d"] = base64.RawURLEncoding.EncodeToString(private.D.Bytes())

	return value
}

func encryptionJWK(keyID string) map[string]any {
	return map[string]any{"kty": "EC", "crv": "P-256", "kid": keyID, "use": "enc"}
}

func TestKeySetRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document func(t *testing.T) []byte
	}{
		{
			name: "duplicate kid",
			document: func(t *testing.T) []byte {
				t.Helper()

				return jwksDocument(t,
					rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey),
					ecJWK(testRSAKeyID, &signingECKey().PublicKey),
				)
			},
		},
		{
			name: "key without a kid",
			document: func(t *testing.T) []byte {
				t.Helper()

				return jwksDocument(t, rsaJWK("", &signingRSAKey().PublicKey))
			},
		},
		{
			name: "RSA key without a modulus",
			document: func(t *testing.T) []byte {
				t.Helper()

				return jwksDocument(t, map[string]any{"kty": "RSA", "kid": testRSAKeyID, "e": "AQAB"})
			},
		},
		{
			name: "not JSON",
			document: func(t *testing.T) []byte {
				t.Helper()

				return []byte("not json")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keys := newJWKSServer(t, test.document(t))
			keySet := newKeySet(t, keys, newTestClock())

			_, err := keySet.Key(t.Context(), testRSAKeyID)
			if !errors.Is(err, externaltoken.ErrInvalidJWKS) {
				t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrInvalidJWKS)
			}
		})
	}
}

func TestKeySetRejectsAnOversizedDocument(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, []byte(`{"padding":"`+strings.Repeat("a", 1<<20)+`"}`))
	keySet := newKeySet(t, keys, newTestClock())

	_, err := keySet.Key(t.Context(), testRSAKeyID)
	if !errors.Is(err, externaltoken.ErrDocumentTooLarge) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrDocumentTooLarge)
	}
}

func TestKeySetRejectsAnEmptyKeyID(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	keySet := newKeySet(t, keys, newTestClock())

	_, err := keySet.Key(t.Context(), "")
	if !errors.Is(err, externaltoken.ErrMissingKeyID) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrMissingKeyID)
	}

	if got := keys.fetches(); got != 0 {
		t.Errorf("fetches = %d, want 0", got)
	}
}

func TestNewKeySetRejectsInvalidURLs(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "/oauth2/jwks", "ftp://idp.example.test/jwks"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			_, err := externaltoken.NewKeySet(externaltoken.KeySetConfig{URL: raw})
			if !errors.Is(err, externaltoken.ErrInvalidJWKSURL) {
				t.Fatalf("NewKeySet() error = %v, want %v", err, externaltoken.ErrInvalidJWKSURL)
			}
		})
	}
}
