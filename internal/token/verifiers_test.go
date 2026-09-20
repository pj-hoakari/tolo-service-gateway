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

func newContextVerifiers(t *testing.T, keys issuer.KeyProvider) *token.ContextVerifiers {
	t.Helper()

	verifiers, err := token.NewContextVerifiers(
		contextIssuerID,
		[]string{serviceA, serviceB},
		token.NewLocalKeyResolver(keys),
	)
	if err != nil {
		t.Fatalf("NewContextVerifiers() error = %v, want nil", err)
	}

	return verifiers
}

func TestContextVerifiersVerifyAcceptsAContextTokenAddressedToThePresenter(t *testing.T) {
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

			claims, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, issued.Token)
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

func TestContextVerifiersVerifyAcceptsAPublishedKey(t *testing.T) {
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

	claims, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, issued.Token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if claims.ID != issued.Claims.ID {
		t.Errorf("jti = %q, want %q", claims.ID, issued.Claims.ID)
	}
}

func TestContextVerifiersVerifyRejectsAnotherServicesContextToken(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	issued := issueExternal(t, newIssuer(t, contextIssuerID, keys), serviceA, time.Now())

	claims, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceB, issued.Token)
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

func TestContextVerifiersVerifyRejectsAnUnknownPresenter(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	issued := issueExternal(t, newIssuer(t, contextIssuerID, keys), serviceA, time.Now())

	_, err := newContextVerifiers(t, keys).Verify(t.Context(), unknownService, issued.Token)
	if !errors.Is(err, token.ErrUnknownService) {
		t.Fatalf("Verify() error = %v, want %v", err, token.ErrUnknownService)
	}
}

func TestContextVerifiersVerifyRejectsAnUnknownKeyID(t *testing.T) {
	t.Parallel()

	issued := issueExternal(
		t,
		newIssuer(t, contextIssuerID, signingProvider(localForeignKeyID, newKey(t))),
		serviceA,
		time.Now(),
	)

	keys := signingProvider(localSigningKeyID, newKey(t))

	_, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, issued.Token)
	if !errors.Is(err, verifier.ErrUnknownKey) {
		t.Fatalf("Verify() error = %v, want %v", err, verifier.ErrUnknownKey)
	}
}

func TestContextVerifiersVerifyRejectsAnotherKeyUnderAKnownKeyID(t *testing.T) {
	t.Parallel()

	issued := issueExternal(
		t,
		newIssuer(t, contextIssuerID, signingProvider(localSigningKeyID, newKey(t))),
		serviceA,
		time.Now(),
	)

	keys := signingProvider(localSigningKeyID, newKey(t))

	_, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, issued.Token)
	if !errors.Is(err, verifier.ErrInvalidToken) {
		t.Fatalf("Verify() error = %v, want %v", err, verifier.ErrInvalidToken)
	}

	if errors.Is(err, verifier.ErrUnknownKey) {
		t.Errorf("Verify() error = %v, want a signature failure rather than an unknown key", err)
	}
}

func TestContextVerifiersVerifyRejectsAnExpiredToken(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	past := time.Now().Add(-10 * time.Minute)
	expiredIssuer := newIssuer(t, contextIssuerID, keys, issuer.WithClock(func() time.Time { return past }))
	issued := issueExternal(t, expiredIssuer, serviceA, past)

	_, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, issued.Token)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrTokenExpired)
	}
}

func TestContextVerifiersVerifyRejectsAnotherIssuer(t *testing.T) {
	t.Parallel()

	keys := signingProvider(localSigningKeyID, newKey(t))
	issued := issueExternal(t, newIssuer(t, "another-gateway", keys), serviceA, time.Now())

	_, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, issued.Token)
	if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrTokenInvalidIssuer)
	}
}

func TestContextVerifiersVerifyRejectsAnOriginClaimViolation(t *testing.T) {
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

			_, err := newContextVerifiers(t, keys).Verify(t.Context(), serviceA, forged)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewContextVerifiers(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		serviceIDs []string
	}{
		"one service ID":   {serviceIDs: []string{serviceA}},
		"two service IDs":  {serviceIDs: []string{serviceA, serviceB}},
		"no service ID":    {serviceIDs: nil},
		"an empty service": {serviceIDs: []string{}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			keys := token.NewLocalKeyResolver(signingProvider(localSigningKeyID, newKey(t)))

			verifiers, err := token.NewContextVerifiers(contextIssuerID, tt.serviceIDs, keys)
			if err != nil {
				t.Fatalf("NewContextVerifiers() error = %v, want nil", err)
			}

			if _, err := verifiers.Verify(t.Context(), unknownService, "token"); !errors.Is(err, token.ErrUnknownService) {
				t.Errorf("Verify() error = %v, want %v", err, token.ErrUnknownService)
			}
		})
	}
}

func TestNewContextVerifiersRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuerID   string
		serviceIDs []string
		wantErr    error
	}{
		"an empty service ID": {
			issuerID:   contextIssuerID,
			serviceIDs: []string{serviceA, ""},
			wantErr:    token.ErrEmptyServiceID,
		},
		"a duplicate service ID": {
			issuerID:   contextIssuerID,
			serviceIDs: []string{serviceA, serviceB, serviceA},
			wantErr:    token.ErrDuplicateServiceID,
		},
		"an empty issuer ID": {
			issuerID:   "",
			serviceIDs: []string{serviceA},
			wantErr:    verifier.ErrMissingIssuerID,
		},
		"an empty issuer ID without any service ID": {
			issuerID:   "",
			serviceIDs: nil,
			wantErr:    verifier.ErrMissingIssuerID,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			keys := token.NewLocalKeyResolver(signingProvider(localSigningKeyID, newKey(t)))

			verifiers, err := token.NewContextVerifiers(tt.issuerID, tt.serviceIDs, keys)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewContextVerifiers() error = %v, want %v", err, tt.wantErr)
			}

			if verifiers != nil {
				t.Errorf("NewContextVerifiers() = %v, want nil", verifiers)
			}
		})
	}
}
