package externaltoken_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
)

const testIssuer = "https://idp.example.test"

type stubKeys struct {
	keys map[string]crypto.PublicKey
	err  error
}

func (s stubKeys) Key(_ context.Context, keyID string) (crypto.PublicKey, error) {
	if s.err != nil {
		return nil, s.err
	}

	key, ok := s.keys[keyID]
	if !ok {
		return nil, externaltoken.ErrUnknownKeyID
	}

	return key, nil
}

func idpKeys() stubKeys {
	return stubKeys{
		keys: map[string]crypto.PublicKey{
			testRSAKeyID: &signingRSAKey().PublicKey,
			testECKeyID:  &signingECKey().PublicKey,
		},
		err: nil,
	}
}

func newVerifier(t *testing.T, keys externaltoken.KeyResolver, algorithms []string, clock func() time.Time) *externaltoken.Verifier {
	t.Helper()

	verifier, err := externaltoken.NewVerifier(externaltoken.Config{
		Issuer:     testIssuer,
		Audience:   testAudience,
		Algorithms: algorithms,
		Keys:       keys,
		Leeway:     0,
		Clock:      clock,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v, want nil", err)
	}

	return verifier
}

func tenantAccessClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":       testIssuer,
		"sub":       testSubject,
		"aud":       testAudience,
		"exp":       now.Add(15 * time.Minute).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"iat":       now.Add(-time.Minute).Unix(),
		"jti":       testJTI,
		"client_id": testClientID,
		"scope":     testScope,
		"token_use": "tenant_access",
		"tenant_id": testTenantID,
		"resource":  "https://api.example.test",
	}
}

func TestVerifierVerify(t *testing.T) {
	t.Parallel()

	clock := newTestClock()

	tests := []struct {
		name    string
		mutate  func(claims jwt.MapClaims)
		want    externaltoken.Claims
		wantErr error
	}{
		{
			name:   "tenant access",
			mutate: func(_ jwt.MapClaims) {},
			want: externaltoken.Claims{
				Subject: testSubject, ClientID: testClientID, TokenUse: "tenant_access",
				Scope: testScope, JTI: testJTI, TenantID: testTenantID, EventID: "",
				ExpiresAt: clock.Now().Add(15 * time.Minute), Confirmation: "",
			},
			wantErr: nil,
		},
		{
			name: "event access",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "event_access"
				claims["event_id"] = testEventID
			},
			want: externaltoken.Claims{
				Subject: testSubject, ClientID: testClientID, TokenUse: "event_access",
				Scope: testScope, JTI: testJTI, TenantID: testTenantID, EventID: testEventID,
				ExpiresAt: clock.Now().Add(15 * time.Minute), Confirmation: "",
			},
			wantErr: nil,
		},
		{
			name: "registration",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "registration"
				delete(claims, "tenant_id")
			},
			want: externaltoken.Claims{
				Subject: testSubject, ClientID: testClientID, TokenUse: "registration",
				Scope: testScope, JTI: testJTI, TenantID: "", EventID: "",
				ExpiresAt: clock.Now().Add(15 * time.Minute), Confirmation: "",
			},
			wantErr: nil,
		},
		{
			name: "audience as a single element array",
			mutate: func(claims jwt.MapClaims) {
				claims["aud"] = []string{testAudience}
			},
			want: externaltoken.Claims{
				Subject: testSubject, ClientID: testClientID, TokenUse: "tenant_access",
				Scope: testScope, JTI: testJTI, TenantID: testTenantID, EventID: "",
				ExpiresAt: clock.Now().Add(15 * time.Minute), Confirmation: "",
			},
			wantErr: nil,
		},
		{
			name: "confirmation claim",
			mutate: func(claims jwt.MapClaims) {
				claims["cnf"] = map[string]any{"jkt": "thumbprint-1"}
			},
			want: externaltoken.Claims{
				Subject: testSubject, ClientID: testClientID, TokenUse: "tenant_access",
				Scope: testScope, JTI: testJTI, TenantID: testTenantID, EventID: "",
				ExpiresAt: clock.Now().Add(15 * time.Minute), Confirmation: "thumbprint-1",
			},
			wantErr: nil,
		},
		{
			name: "audience holds two values",
			mutate: func(claims jwt.MapClaims) {
				claims["aud"] = []string{testAudience, "other-api"}
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "audience is absent",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "aud")
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "audience is another API",
			mutate: func(claims jwt.MapClaims) {
				claims["aud"] = "other-api"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "issuer differs",
			mutate: func(claims jwt.MapClaims) {
				claims["iss"] = testIssuer + "/"
			},
			wantErr: externaltoken.ErrInvalidToken,
		},
		{
			name: "expiry is absent",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "exp")
			},
			wantErr: externaltoken.ErrInvalidToken,
		},
		{
			name: "subject is absent",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "sub")
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "token id is empty",
			mutate: func(claims jwt.MapClaims) {
				claims["jti"] = ""
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "client id is absent",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "client_id")
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "scope is a list",
			mutate: func(claims jwt.MapClaims) {
				claims["scope"] = []string{"tenant.read"}
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "token use is service",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "service"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "token use is unknown",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "admin"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "tenant access carries an event id",
			mutate: func(claims jwt.MapClaims) {
				claims["event_id"] = testEventID
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "tenant access without a tenant id",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "tenant_id")
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "event access without an event id",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "event_access"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "registration carries a tenant id",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "registration"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "tenant id is uppercase hex",
			mutate: func(claims jwt.MapClaims) {
				claims["tenant_id"] = "0123456789ABCDEF"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "tenant id is too short",
			mutate: func(claims jwt.MapClaims) {
				claims["tenant_id"] = "0123456789abcde"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "event id is not hex",
			mutate: func(claims jwt.MapClaims) {
				claims["token_use"] = "event_access"
				claims["event_id"] = "zzzzzzzzzzzzzzzz"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "confirmation is not an object",
			mutate: func(claims jwt.MapClaims) {
				claims["cnf"] = "thumbprint-1"
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
		{
			name: "confirmation has no thumbprint",
			mutate: func(claims jwt.MapClaims) {
				claims["cnf"] = map[string]any{"x5t#S256": "other"}
			},
			wantErr: externaltoken.ErrInvalidClaims,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			claims := tenantAccessClaims(clock.Now())
			test.mutate(claims)

			token := signToken(t, jwt.SigningMethodRS256, signingRSAKey(), testRSAKeyID, claims)
			verifier := newVerifier(t, idpKeys(), nil, clock.Now)

			got, err := verifier.Verify(t.Context(), token)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Verify() error = %v, want %v", err, test.wantErr)
				}

				if strings.Contains(err.Error(), token) {
					t.Errorf("Verify() error message contains the token")
				}

				return
			}

			if err != nil {
				t.Fatalf("Verify() error = %v, want nil", err)
			}

			if got != test.want {
				t.Errorf("Verify() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestVerifierRejectsForgedTokens(t *testing.T) {
	t.Parallel()

	clock := newTestClock()

	tests := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{
			name: "alg none",
			token: func(t *testing.T) string {
				t.Helper()

				return signToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType,
					testRSAKeyID, tenantAccessClaims(clock.Now()))
			},
		},
		{
			name: "HMAC over the public key",
			token: func(t *testing.T) string {
				t.Helper()

				encoded, err := x509.MarshalPKIXPublicKey(&signingRSAKey().PublicKey)
				if err != nil {
					t.Fatalf("MarshalPKIXPublicKey() error = %v, want nil", err)
				}

				return signToken(t, jwt.SigningMethodHS256, encoded, testRSAKeyID, tenantAccessClaims(clock.Now()))
			},
		},
		{
			name: "no kid",
			token: func(t *testing.T) string {
				t.Helper()

				return signToken(t, jwt.SigningMethodRS256, signingRSAKey(), "", tenantAccessClaims(clock.Now()))
			},
		},
		{
			name: "unknown kid",
			token: func(t *testing.T) string {
				t.Helper()

				return signToken(t, jwt.SigningMethodRS256, signingRSAKey(), "rotated-key", tenantAccessClaims(clock.Now()))
			},
		},
		{
			name: "RS256 header over an EC key",
			token: func(t *testing.T) string {
				t.Helper()

				return signToken(t, jwt.SigningMethodRS256, signingRSAKey(), testECKeyID, tenantAccessClaims(clock.Now()))
			},
		},
		{
			name: "signed by another RSA key",
			token: func(t *testing.T) string {
				t.Helper()

				return signToken(t, jwt.SigningMethodRS256, generateRSAKey(2048), testRSAKeyID, tenantAccessClaims(clock.Now()))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			token := test.token(t)
			verifier := newVerifier(t, idpKeys(), nil, clock.Now)

			_, err := verifier.Verify(t.Context(), token)
			if !errors.Is(err, externaltoken.ErrInvalidToken) {
				t.Fatalf("Verify() error = %v, want %v", err, externaltoken.ErrInvalidToken)
			}

			if strings.Contains(err.Error(), token) {
				t.Errorf("Verify() error message contains the token")
			}
		})
	}
}

func TestVerifierAcceptsES256WhenConfigured(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	token := signToken(t, jwt.SigningMethodES256, signingECKey(), testECKeyID, tenantAccessClaims(clock.Now()))
	verifier := newVerifier(t, idpKeys(), []string{"ES256"}, clock.Now)

	got, err := verifier.Verify(t.Context(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if got.TenantID != testTenantID {
		t.Errorf("Verify() tenant_id = %q, want %q", got.TenantID, testTenantID)
	}

	rejecting := newVerifier(t, idpKeys(), nil, clock.Now)

	if _, err := rejecting.Verify(t.Context(), token); !errors.Is(err, externaltoken.ErrInvalidToken) {
		t.Fatalf("Verify() with RS256 only error = %v, want %v", err, externaltoken.ErrInvalidToken)
	}
}

func TestVerifierLeeway(t *testing.T) {
	t.Parallel()

	clock := newTestClock()

	tests := []struct {
		name    string
		shift   func(claims jwt.MapClaims)
		wantErr bool
	}{
		{
			name: "expired within the leeway",
			shift: func(claims jwt.MapClaims) {
				claims["exp"] = clock.Now().Add(-20 * time.Second).Unix()
			},
			wantErr: false,
		},
		{
			name: "expired past the leeway",
			shift: func(claims jwt.MapClaims) {
				claims["exp"] = clock.Now().Add(-40 * time.Second).Unix()
			},
			wantErr: true,
		},
		{
			name: "not before within the leeway",
			shift: func(claims jwt.MapClaims) {
				claims["nbf"] = clock.Now().Add(20 * time.Second).Unix()
			},
			wantErr: false,
		},
		{
			name: "not before past the leeway",
			shift: func(claims jwt.MapClaims) {
				claims["nbf"] = clock.Now().Add(40 * time.Second).Unix()
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			claims := tenantAccessClaims(clock.Now())
			test.shift(claims)

			token := signToken(t, jwt.SigningMethodRS256, signingRSAKey(), testRSAKeyID, claims)
			verifier := newVerifier(t, idpKeys(), nil, clock.Now)

			_, err := verifier.Verify(t.Context(), token)
			if test.wantErr && !errors.Is(err, externaltoken.ErrInvalidToken) {
				t.Fatalf("Verify() error = %v, want %v", err, externaltoken.ErrInvalidToken)
			}

			if !test.wantErr && err != nil {
				t.Fatalf("Verify() error = %v, want nil", err)
			}
		})
	}
}

func TestVerifierReportsUnavailableKeys(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	token := signToken(t, jwt.SigningMethodRS256, signingRSAKey(), testRSAKeyID, tenantAccessClaims(clock.Now()))
	keys := stubKeys{keys: nil, err: externaltoken.ErrKeysUnavailable}
	verifier := newVerifier(t, keys, nil, clock.Now)

	_, err := verifier.Verify(t.Context(), token)
	if !errors.Is(err, externaltoken.ErrKeysUnavailable) {
		t.Fatalf("Verify() error = %v, want %v", err, externaltoken.ErrKeysUnavailable)
	}

	if errors.Is(err, externaltoken.ErrInvalidClaims) {
		t.Errorf("Verify() error = %v, want it not to be %v", err, externaltoken.ErrInvalidClaims)
	}

	if strings.Contains(err.Error(), token) {
		t.Errorf("Verify() error message contains the token")
	}
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config externaltoken.Config
	}{
		{name: "no issuer", config: externaltoken.Config{Audience: testAudience, Keys: idpKeys()}},
		{name: "no audience", config: externaltoken.Config{Issuer: testIssuer, Keys: idpKeys()}},
		{name: "no key resolver", config: externaltoken.Config{Issuer: testIssuer, Audience: testAudience}},
		{
			name: "alg none",
			config: externaltoken.Config{
				Issuer: testIssuer, Audience: testAudience, Keys: idpKeys(), Algorithms: []string{"none"},
			},
		},
		{
			name: "HS256",
			config: externaltoken.Config{
				Issuer: testIssuer, Audience: testAudience, Keys: idpKeys(), Algorithms: []string{"HS256"},
			},
		},
		{
			name: "RS256 and HS256",
			config: externaltoken.Config{
				Issuer: testIssuer, Audience: testAudience, Keys: idpKeys(), Algorithms: []string{"RS256", "HS256"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := externaltoken.NewVerifier(test.config); !errors.Is(err, externaltoken.ErrInvalidConfig) {
				t.Fatalf("NewVerifier() error = %v, want %v", err, externaltoken.ErrInvalidConfig)
			}
		})
	}
}
