package externaltoken_test

import (
	"context"
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
	mu            sync.Mutex
	document      []byte
	status        int
	delay         time.Duration
	requests      int
	failures      int
	failureStatus int
	resets        int
	onRequest     func()

	server *httptest.Server
}

func newJWKSServer(t *testing.T, document []byte) *jwksServer {
	t.Helper()

	keys := &jwksServer{
		document:      document,
		status:        http.StatusOK,
		delay:         0,
		requests:      0,
		failures:      0,
		failureStatus: http.StatusServiceUnavailable,
		resets:        0,
		onRequest:     nil,
		server:        nil,
	}

	keys.server = httptest.NewServer(http.HandlerFunc(keys.serve))
	t.Cleanup(keys.server.Close)

	return keys
}

func (s *jwksServer) serve(writer http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.requests++
	document, status, delay, notify := s.document, s.status, s.delay, s.onRequest
	reset := s.resets > 0

	switch {
	case reset:
		s.resets--
	case s.failures > 0:
		s.failures--
		document, status = nil, s.failureStatus
	}

	s.mu.Unlock()

	if notify != nil {
		notify()
	}

	time.Sleep(delay)

	if reset {
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}

		return
	}

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

func (s *jwksServer) failFirst(count, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failures, s.failureStatus = count, status
}

func (s *jwksServer) resetFirst(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resets = count
}

func (s *jwksServer) notify(hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.onRequest = hook
}

func (s *jwksServer) fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.requests
}

var testRetryBackoff = []time.Duration{time.Millisecond, 2 * time.Millisecond}

func newKeySet(t *testing.T, keys *jwksServer, clock *testClock) *externaltoken.KeySet {
	t.Helper()

	return newRetryingKeySet(t, keys, clock, []time.Duration{})
}

func newRetryingKeySet(
	t *testing.T,
	keys *jwksServer,
	clock *testClock,
	backoff []time.Duration,
) *externaltoken.KeySet {
	t.Helper()

	keySet, err := externaltoken.NewKeySet(externaltoken.KeySetConfig{
		URL:             keys.server.URL,
		HTTPClient:      keys.server.Client(),
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    0,
		RetryBackoff:    backoff,
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

func TestKeySetRetriesATransientStatus(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	keys.failFirst(1, http.StatusServiceUnavailable)

	keySet := newRetryingKeySet(t, keys, newTestClock(), testRetryBackoff)

	mustKey(t, keySet, testRSAKeyID)

	if got := keys.fetches(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}

	mustKey(t, keySet, testRSAKeyID)

	if got := keys.fetches(); got != 2 {
		t.Errorf("fetches after a successful retry = %d, want 2", got)
	}
}

func TestKeySetRetriesAConnectionFailure(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, jwksDocument(t, rsaJWK(testRSAKeyID, &signingRSAKey().PublicKey)))
	keys.resetFirst(1)

	keySet := newRetryingKeySet(t, keys, newTestClock(), testRetryBackoff)

	mustKey(t, keySet, testRSAKeyID)

	if got := keys.fetches(); got != 2 {
		t.Errorf("fetches = %d, want 2", got)
	}
}

func TestKeySetRetriesOnlyTransientStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		want   int
	}{
		{name: "service unavailable", status: http.StatusServiceUnavailable, want: 3},
		{name: "bad gateway", status: http.StatusBadGateway, want: 3},
		{name: "too many requests", status: http.StatusTooManyRequests, want: 3},
		{name: "not found", status: http.StatusNotFound, want: 1},
		{name: "bad request", status: http.StatusBadRequest, want: 1},
		{name: "forbidden", status: http.StatusForbidden, want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keys := newJWKSServer(t, nil)
			keys.serveDocument(nil, test.status)

			keySet := newRetryingKeySet(t, keys, newTestClock(), testRetryBackoff)

			if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
				t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
			}

			if got := keys.fetches(); got != test.want {
				t.Errorf("fetches = %d, want %d", got, test.want)
			}
		})
	}
}

func TestKeySetDoesNotRetryAPermanentlyBadDocument(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document []byte
		wantErr  error
	}{
		{name: "not JSON", document: []byte("not json"), wantErr: externaltoken.ErrInvalidJWKS},
		{
			name:     "too large",
			document: []byte(`{"padding":"` + strings.Repeat("a", 1<<20) + `"}`),
			wantErr:  externaltoken.ErrDocumentTooLarge,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			keys := newJWKSServer(t, test.document)
			keySet := newRetryingKeySet(t, keys, newTestClock(), testRetryBackoff)

			if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, test.wantErr) {
				t.Fatalf("Key() error = %v, want %v", err, test.wantErr)
			}

			if got := keys.fetches(); got != 1 {
				t.Errorf("fetches = %d, want 1", got)
			}
		})
	}
}

func TestKeySetEntersTheFailureCooldownOnlyAfterEveryAttempt(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, nil)
	keys.serveDocument(nil, http.StatusServiceUnavailable)

	clock := newTestClock()
	keySet := newRetryingKeySet(t, keys, clock, testRetryBackoff)

	attempts := 1 + len(testRetryBackoff)

	if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	if got := keys.fetches(); got != attempts {
		t.Fatalf("fetches = %d, want %d", got, attempts)
	}

	if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() during the failure cooldown error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	if got := keys.fetches(); got != attempts {
		t.Errorf("fetches during the failure cooldown = %d, want %d", got, attempts)
	}

	clock.advance(externaltoken.DefaultFailureCooldown)

	if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() after the failure cooldown error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	if got := keys.fetches(); got != 2*attempts {
		t.Errorf("fetches after the failure cooldown = %d, want %d", got, 2*attempts)
	}
}

func TestKeySetUsesTheDefaultRetryBackoff(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, nil)
	keys.serveDocument(nil, http.StatusServiceUnavailable)

	keySet := newRetryingKeySet(t, keys, newTestClock(), nil)

	if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	want := 1 + len(externaltoken.DefaultRetryBackoff())
	if got := keys.fetches(); got != want {
		t.Errorf("fetches = %d, want %d", got, want)
	}
}

func TestKeySetWithoutRetryBackoffFetchesOnce(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, nil)
	keys.serveDocument(nil, http.StatusServiceUnavailable)

	keySet := newRetryingKeySet(t, keys, newTestClock(), []time.Duration{})

	if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Key() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	if got := keys.fetches(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

func TestKeySetStopsRetryingWhenTheContextIsCanceled(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, nil)
	keys.serveDocument(nil, http.StatusServiceUnavailable)

	keySet := newRetryingKeySet(t, keys, newTestClock(), []time.Duration{time.Minute, time.Minute})

	for attempt, want := range []int{1, 2} {
		ctx, cancel := context.WithCancel(t.Context())
		keys.notify(cancel)

		start := time.Now()
		_, err := keySet.Key(ctx, testRSAKeyID)

		cancel()

		if !errors.Is(err, externaltoken.ErrKeysUnavailable) {
			t.Fatalf("Key() %d error = %v, want %v", attempt, err, externaltoken.ErrKeysUnavailable)
		}

		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Fatalf("Key() %d took %s, want it to stop waiting on the cancellation", attempt, elapsed)
		}

		if got := keys.fetches(); got != want {
			t.Fatalf("fetches after %d cancellations = %d, want %d", attempt+1, got, want)
		}
	}
}

func TestKeySetCoalescesConcurrentFetchesAcrossRetries(t *testing.T) {
	t.Parallel()

	keys := newJWKSServer(t, nil)
	keys.serveDocument(nil, http.StatusServiceUnavailable)
	keys.setDelay(20 * time.Millisecond)

	backoff := []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	keySet := newRetryingKeySet(t, keys, newTestClock(), backoff)

	var waiting sync.WaitGroup

	for range 8 {
		waiting.Add(1)

		go func() {
			defer waiting.Done()

			if _, err := keySet.Key(t.Context(), testRSAKeyID); !errors.Is(err, externaltoken.ErrKeysUnavailable) {
				t.Errorf("Key() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
			}
		}()
	}

	waiting.Wait()

	want := 1 + len(backoff)
	if got := keys.fetches(); got != want {
		t.Errorf("fetches = %d, want %d", got, want)
	}
}

func TestNewKeySetRejectsANegativeRetryBackoff(t *testing.T) {
	t.Parallel()

	_, err := externaltoken.NewKeySet(externaltoken.KeySetConfig{
		URL:          "https://idp.example.test/jwks",
		RetryBackoff: []time.Duration{time.Millisecond, -time.Millisecond},
	})
	if !errors.Is(err, externaltoken.ErrInvalidRetryBackoff) {
		t.Fatalf("NewKeySet() error = %v, want %v", err, externaltoken.ErrInvalidRetryBackoff)
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
