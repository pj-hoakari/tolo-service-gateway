package token_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	"github.com/pj-hoakari/tolo-service-gateway/internal/token"
)

func newContextVerifier(t *testing.T, keys issuer.KeyProvider) *verifier.ContextVerifier {
	t.Helper()

	contextVerifier, err := token.NewContextVerifier(contextIssuerID, keys)
	if err != nil {
		t.Fatalf("NewContextVerifier() error = %v, want nil", err)
	}

	return contextVerifier
}

func TestContextVerifierVerifyAcceptsAContextTokenAddressedToThePresenter(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issue        func(t *testing.T, internalIssuer *issuer.Issuer) issuer.Issued
		wantTokenUse string
	}{
		"a user-origin token converted from an external one": {
			issue: func(t *testing.T, internalIssuer *issuer.Issuer) issuer.Issued {
				t.Helper()

				return issueExternal(t, internalIssuer, serviceA, time.Now())
			},
			wantTokenUse: internaljwt.TokenUseTenantAccess,
		},
		"a machine-origin service token": {
			issue: func(t *testing.T, internalIssuer *issuer.Issuer) issuer.Issued {
				t.Helper()

				return issueMachineOriginService(t, internalIssuer, serviceA, serviceB)
			},
			wantTokenUse: internaljwt.TokenUseService,
		},
		"a user-origin service token": {
			issue: func(t *testing.T, internalIssuer *issuer.Issuer) issuer.Issued {
				t.Helper()

				return issueUserOriginService(t, internalIssuer, serviceA, serviceB, time.Now())
			},
			wantTokenUse: internaljwt.TokenUseService,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			keys := signingProvider(localSigningKeyID, newKey(t))
			issued := tt.issue(t, newIssuer(t, contextIssuerID, keys))

			claims, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
			if err != nil {
				t.Fatalf("Verify() error = %v, want nil", err)
			}

			if len(claims.Audience) != 1 || claims.Audience[0] != serviceA {
				t.Errorf("aud = %v, want [%q]", claims.Audience, serviceA)
			}

			if claims.TokenUse != tt.wantTokenUse {
				t.Errorf("token_use = %q, want %q", claims.TokenUse, tt.wantTokenUse)
			}

			if claims.ID != issued.Claims.ID {
				t.Errorf("jti = %q, want %q", claims.ID, issued.Claims.ID)
			}
		})
	}
}

func TestContextVerifierVerifyAcceptsAPublishedKey(t *testing.T) {
	t.Parallel()

	rotatedKey := newKey(t)
	issued := issueExternal(
		t,
		newIssuer(t, contextIssuerID, signingProvider(localRotatedKeyID, rotatedKey)),
		serviceA,
		time.Now(),
	)

	keys := signingProvider(
		localSigningKeyID,
		newKey(t),
		issuer.PublishedKey{KeyID: localRotatedKeyID, Key: &rotatedKey.PublicKey},
	)

	claims, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if claims.ID != issued.Claims.ID {
		t.Errorf("jti = %q, want %q", claims.ID, issued.Claims.ID)
	}
}

func TestContextVerifierVerifyRejectsAnotherServicesContextToken(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	issued := issueExternal(t, newIssuer(t, contextIssuerID, keys), serviceA, time.Now())

	claims, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceB)
	if !errors.Is(err, verifier.ErrInvalidToken) {
		t.Fatalf("Verify() error = %v, want %v", err, verifier.ErrInvalidToken)
	}

	if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
		t.Errorf("Verify() error = %v, want %v", err, jwt.ErrTokenInvalidAudience)
	}

	if claims.ID != "" {
		t.Errorf("Verify() claims = %+v, want the zero value", claims)
	}
}

func TestContextVerifierVerifyRejectsAnEmptyPresenter(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	issued := issueExternal(t, newIssuer(t, contextIssuerID, keys), serviceA, time.Now())

	claims, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, "")
	if !errors.Is(err, verifier.ErrMissingAudience) {
		t.Fatalf("Verify() error = %v, want %v", err, verifier.ErrMissingAudience)
	}

	if claims.ID != "" {
		t.Errorf("Verify() claims = %+v, want the zero value", claims)
	}
}

func TestContextVerifierVerifyRejectsAnUnknownKeyID(t *testing.T) {
	t.Parallel()

	issued := issueExternal(
		t,
		newIssuer(t, contextIssuerID, signingProvider(localForeignKeyID, newKey(t))),
		serviceA,
		time.Now(),
	)

	keys := signingProvider(localSigningKeyID, newKey(t))

	_, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
	if !errors.Is(err, internaljwt.ErrUnknownKeyID) {
		t.Fatalf("Verify() error = %v, want %v", err, internaljwt.ErrUnknownKeyID)
	}
}

func TestContextVerifierVerifyRejectsAnotherKeyUnderAKnownKeyID(t *testing.T) {
	t.Parallel()

	issued := issueExternal(
		t,
		newIssuer(t, contextIssuerID, signingProvider(localSigningKeyID, newKey(t))),
		serviceA,
		time.Now(),
	)

	keys := signingProvider(localSigningKeyID, newKey(t))

	_, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
	if !errors.Is(err, verifier.ErrInvalidToken) {
		t.Fatalf("Verify() error = %v, want %v", err, verifier.ErrInvalidToken)
	}

	if errors.Is(err, internaljwt.ErrUnknownKeyID) {
		t.Errorf("Verify() error = %v, want a signature failure rather than an unknown key", err)
	}
}

func TestContextVerifierVerifyReportsAKeyProviderFailure(t *testing.T) {
	t.Parallel()

	issued := issueExternal(
		t,
		newIssuer(t, contextIssuerID, signingProvider(localSigningKeyID, newKey(t))),
		serviceA,
		time.Now(),
	)

	keys := staticKeyProvider{keySet: issuer.KeySet{}, err: errKeyProviderDown}

	_, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
	if !errors.Is(err, verifier.ErrKeyResolution) {
		t.Fatalf("Verify() error = %v, want %v", err, verifier.ErrKeyResolution)
	}

	if !errors.Is(err, errKeyProviderDown) {
		t.Errorf("Verify() error = %v, want %v", err, errKeyProviderDown)
	}

	if errors.Is(err, verifier.ErrInvalidToken) {
		t.Errorf("Verify() error = %v, want it to not be %v", err, verifier.ErrInvalidToken)
	}

	if errors.Is(err, internaljwt.ErrUnknownKeyID) {
		t.Errorf("Verify() error = %v, want it to not be %v", err, internaljwt.ErrUnknownKeyID)
	}
}

func TestContextVerifierVerifyRejectsAnExpiredToken(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	past := time.Now().Add(-10 * time.Minute)
	expiredIssuer := newIssuer(t, contextIssuerID, keys, issuer.WithClock(func() time.Time { return past }))
	issued := issueExternal(t, expiredIssuer, serviceA, past)

	_, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrTokenExpired)
	}
}

func TestContextVerifierVerifyRejectsAnotherIssuer(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	issued := issueExternal(t, newIssuer(t, "another-gateway", keys), serviceA, time.Now())

	_, err := newContextVerifier(t, keys).Verify(t.Context(), issued.Token, serviceA)
	if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrTokenInvalidIssuer)
	}
}

func TestContextVerifierVerifyRejectsAnOriginClaimViolation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		claims  func(now time.Time) internaljwt.Claims
		wantErr error
	}{
		"a machine-origin service token carrying a scope": {
			claims: func(now time.Time) internaljwt.Claims {
				claims := machineOriginClaims(serviceA, serviceB, now)
				claims.Scope = testScope

				return claims
			},
			wantErr: verifier.ErrForbiddenClaim,
		},
		"a machine-origin service token carrying a tenant ID": {
			claims: func(now time.Time) internaljwt.Claims {
				claims := machineOriginClaims(serviceA, serviceB, now)
				claims.TenantPublicID = testTenantPublicID

				return claims
			},
			wantErr: verifier.ErrForbiddenClaim,
		},
		"a user-origin service token without a scope": {
			claims: func(now time.Time) internaljwt.Claims {
				claims := machineOriginClaims(serviceA, serviceB, now)
				claims.OriginSub = testUserSubject
				claims.SourceJTI = testSourceJTI

				return claims
			},
			wantErr: verifier.ErrMissingClaim,
		},
		"a tenant_access token without a tenant ID": {
			claims: func(now time.Time) internaljwt.Claims {
				claims := tenantAccessClaims(serviceA, now)
				claims.TenantPublicID = ""

				return claims
			},
			wantErr: internaljwt.ErrMissingTenantPublicID,
		},
		"a service token whose client_id is not its sub": {
			claims: func(now time.Time) internaljwt.Claims {
				claims := machineOriginClaims(serviceA, serviceB, now)
				claims.ClientID = testClientID

				return claims
			},
			wantErr: verifier.ErrClientIDMismatch,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signingKey := newKey(t)
			keys := signingProvider(localSigningKeyID, signingKey)
			forged := forgeToken(t, localSigningKeyID, signingKey, tt.claims(time.Now()))

			_, err := newContextVerifier(t, keys).Verify(t.Context(), forged, serviceA)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewContextVerifierRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuerID string
		keys     issuer.KeyProvider
		wantErr  error
	}{
		"an empty issuer ID": {
			issuerID: "",
			keys:     signingProvider(localSigningKeyID, newKey(t)),
			wantErr:  verifier.ErrMissingIssuerID,
		},
		"a nil key provider": {
			issuerID: contextIssuerID,
			keys:     nil,
			wantErr:  verifier.ErrMissingKeyResolver,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			contextVerifier, err := token.NewContextVerifier(tt.issuerID, tt.keys)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewContextVerifier() error = %v, want %v", err, tt.wantErr)
			}

			if contextVerifier != nil {
				t.Errorf("NewContextVerifier() = %v, want nil", contextVerifier)
			}
		})
	}
}
