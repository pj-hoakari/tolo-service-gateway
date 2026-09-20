package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
)

const (
	contextIssuerID = "service-gateway"
	serviceA        = "tolo-tenant-management"
	serviceB        = "tolo-event-management"
	unknownService  = "tolo-unregistered"

	localSigningKeyID = "local-key-2"
	localRotatedKeyID = "local-key-1"
	localForeignKeyID = "foreign-key"

	testTenantPublicID = "0123456789abcdef"
	testScope          = "tenant.read tenant.write"
	testUserSubject    = "user-1"
	testClientID       = "admin-ui"
	testSourceJTI      = "external-jti-1"
)

type staticKeyProvider struct {
	keySet issuer.KeySet
	err    error
}

func (p staticKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	if p.err != nil {
		return issuer.KeySet{}, p.err
	}

	return p.keySet, nil
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	return key
}

func signingProvider(keyID string, key *ecdsa.PrivateKey, published ...issuer.PublishedKey) staticKeyProvider {
	return staticKeyProvider{
		keySet: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: keyID, Key: key},
			Published: published,
		},
		err: nil,
	}
}

func newIssuer(t *testing.T, issuerID string, keys issuer.KeyProvider, opts ...issuer.Option) *issuer.Issuer {
	t.Helper()

	internalIssuer, err := issuer.New(issuerID, keys, opts...)
	if err != nil {
		t.Fatalf("issuer.New() error = %v, want nil", err)
	}

	return internalIssuer
}

func issueExternal(t *testing.T, internalIssuer *issuer.Issuer, audience string, now time.Time) issuer.Issued {
	t.Helper()

	issued, err := internalIssuer.IssueFromExternal(t.Context(), issuer.ExternalTokenInput{
		Audience:        audience,
		TokenUse:        internaljwt.TokenUseTenantAccess,
		Subject:         testUserSubject,
		ClientID:        testClientID,
		Scope:           testScope,
		SourceJTI:       testSourceJTI,
		SourceExpiresAt: now.Add(15 * time.Minute),
		TenantPublicID:  testTenantPublicID,
		EventPublicID:   "",
	})
	if err != nil {
		t.Fatalf("IssueFromExternal() error = %v, want nil", err)
	}

	return issued
}

func issueUserOriginService(t *testing.T, internalIssuer *issuer.Issuer, audience, caller string, now time.Time) issuer.Issued {
	t.Helper()

	contextToken := issueExternal(t, internalIssuer, caller, now)

	issued, err := internalIssuer.IssueUserOriginService(t.Context(), issuer.UserOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       contextToken.Claims,
	})
	if err != nil {
		t.Fatalf("IssueUserOriginService() error = %v, want nil", err)
	}

	return issued
}

func issueMachineOriginService(t *testing.T, internalIssuer *issuer.Issuer, audience, caller string) issuer.Issued {
	t.Helper()

	issued, err := internalIssuer.IssueMachineOriginService(t.Context(), issuer.MachineOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       nil,
	})
	if err != nil {
		t.Fatalf("IssueMachineOriginService() error = %v, want nil", err)
	}

	return issued
}

func forgeToken(t *testing.T, keyID string, key *ecdsa.PrivateKey, claims internaljwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v, want nil", err)
	}

	return signed
}

func machineOriginClaims(audience, caller string, now time.Time) internaljwt.Claims {
	return internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    contextIssuerID,
			Subject:   caller,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "jti-1",
		},
		TokenUse:       internaljwt.TokenUseService,
		ClientID:       caller,
		Txn:            "txn-1",
		Scope:          "",
		SourceJTI:      "",
		OriginSub:      "",
		TenantPublicID: "",
		EventPublicID:  "",
	}
}

func tenantAccessClaims(audience string, now time.Time) internaljwt.Claims {
	return internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    contextIssuerID,
			Subject:   testUserSubject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "jti-1",
		},
		TokenUse:       internaljwt.TokenUseTenantAccess,
		ClientID:       testClientID,
		Txn:            "txn-1",
		Scope:          testScope,
		SourceJTI:      testSourceJTI,
		OriginSub:      "",
		TenantPublicID: testTenantPublicID,
		EventPublicID:  "",
	}
}
