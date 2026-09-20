package externaltoken_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testAudience  = "backend-api"
	testTenantID  = "0123456789abcdef"
	testEventID   = "fedcba9876543210"
	testRSAKeyID  = "idp-rsa-1"
	testECKeyID   = "idp-ec-1"
	testWeakKeyID = "idp-weak-1"
	testEncKeyID  = "idp-enc-1"
	testClientID  = "bff"
	testSubject   = "user-1"
	testJTI       = "external-jti-1"
	testScope     = "tenant.read tenant.write"
)

var (
	signingRSAKey = sync.OnceValue(func() *rsa.PrivateKey { return generateRSAKey(2048) })
	weakRSAKey    = sync.OnceValue(func() *rsa.PrivateKey { return generateRSAKey(1024) })
	signingECKey  = sync.OnceValue(func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		return key
	})
)

func generateRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return key
}

func rsaJWK(keyID string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func ecJWK(keyID string, key *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": keyID,
		"use": "sig",
		"alg": "ES256",
		"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

func jwksDocument(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	return encoded
}

func signToken(t *testing.T, method jwt.SigningMethod, key any, keyID string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(method, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v, want nil", err)
	}

	return signed
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, time.September, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) advance(step time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(step)
}
