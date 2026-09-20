package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	"github.com/pj-hoakari/tolo-service-gateway/internal/token"
)

const (
	testIssuerID       = "service-gateway"
	testAudience       = "tolo-tenant-management"
	testSigningKeyID   = "dev-key-1"
	testPublishedKeyID = "next-key"
)

type keySetResolver struct {
	keys issuer.KeyProvider
}

func (r keySetResolver) Key(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	keySet, err := r.keys.Current(ctx)
	if err != nil {
		return nil, err
	}

	if keySet.Signing.Key != nil && keySet.Signing.KeyID == keyID {
		return &keySet.Signing.Key.PublicKey, nil
	}

	for _, published := range keySet.Published {
		if published.KeyID == keyID {
			return published.Key, nil
		}
	}

	return nil, fmt.Errorf("no key for kid %q", keyID)
}

func TestNewIssuerFromFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	signingKeyPath := filepath.Join(dir, "signing-key.pem")
	publishedKeyPath := filepath.Join(dir, "next-key.pub.pem")

	writePrivateKeyPEM(t, signingKeyPath, elliptic.P256())
	writePublicKeyPEM(t, publishedKeyPath, elliptic.P256())

	internalIssuer, keys, err := token.NewIssuerFromFiles(testIssuerID, token.FileKeys{
		Signing: issuer.KeyFile{Path: signingKeyPath, KeyID: testSigningKeyID},
		Published: []issuer.KeyFile{
			{Path: publishedKeyPath, KeyID: testPublishedKeyID},
		},
	})
	if err != nil {
		t.Fatalf("NewIssuerFromFiles() error = %v, want nil", err)
	}

	ctx := t.Context()

	keySet, err := keys.Current(ctx)
	if err != nil {
		t.Fatalf("Current() error = %v, want nil", err)
	}

	if keySet.Signing.KeyID != testSigningKeyID {
		t.Errorf("signing kid = %q, want %q", keySet.Signing.KeyID, testSigningKeyID)
	}

	if len(keySet.Published) != 1 || keySet.Published[0].KeyID != testPublishedKeyID {
		t.Errorf("published keys = %+v, want one key named %q", keySet.Published, testPublishedKeyID)
	}

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

	tokenVerifier, err := verifier.New(testIssuerID, testAudience, keySetResolver{keys: keys})
	if err != nil {
		t.Fatalf("verifier.New() error = %v, want nil", err)
	}

	claims, err := tokenVerifier.Verify(ctx, issued.Token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	if claims.Subject != "user-1" {
		t.Errorf("sub = %q, want %q", claims.Subject, "user-1")
	}

	if claims.TokenUse != internaljwt.TokenUseTenantAccess {
		t.Errorf("token_use = %q, want %q", claims.TokenUse, internaljwt.TokenUseTenantAccess)
	}

	if claims.TenantPublicID != "0123456789abcdef" {
		t.Errorf("tenant_id = %q, want %q", claims.TenantPublicID, "0123456789abcdef")
	}
}

func TestNewIssuerFromFilesRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuerID   string
		signingKey func(t *testing.T, dir string) issuer.KeyFile
	}{
		"the signing key file does not exist": {
			issuerID: testIssuerID,
			signingKey: func(_ *testing.T, dir string) issuer.KeyFile {
				return issuer.KeyFile{Path: filepath.Join(dir, "absent.pem"), KeyID: testSigningKeyID}
			},
		},
		"the signing key file holds no PEM block": {
			issuerID: testIssuerID,
			signingKey: func(t *testing.T, dir string) issuer.KeyFile {
				t.Helper()

				path := filepath.Join(dir, "not-pem.pem")
				if err := os.WriteFile(path, []byte("this is not a PEM file"), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v, want nil", err)
				}

				return issuer.KeyFile{Path: path, KeyID: testSigningKeyID}
			},
		},
		"the signing key is not on P-256": {
			issuerID: testIssuerID,
			signingKey: func(t *testing.T, dir string) issuer.KeyFile {
				t.Helper()

				path := filepath.Join(dir, "p384.pem")
				writePrivateKeyPEM(t, path, elliptic.P384())

				return issuer.KeyFile{Path: path, KeyID: testSigningKeyID}
			},
		},
		"the signing key has no key ID": {
			issuerID: testIssuerID,
			signingKey: func(t *testing.T, dir string) issuer.KeyFile {
				t.Helper()

				path := filepath.Join(dir, "signing-key.pem")
				writePrivateKeyPEM(t, path, elliptic.P256())

				return issuer.KeyFile{Path: path, KeyID: ""}
			},
		},
		"the issuer ID is empty": {
			issuerID: "",
			signingKey: func(t *testing.T, dir string) issuer.KeyFile {
				t.Helper()

				path := filepath.Join(dir, "signing-key.pem")
				writePrivateKeyPEM(t, path, elliptic.P256())

				return issuer.KeyFile{Path: path, KeyID: testSigningKeyID}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			signingKey := tt.signingKey(t, t.TempDir())

			internalIssuer, keys, err := token.NewIssuerFromFiles(tt.issuerID, token.FileKeys{
				Signing:   signingKey,
				Published: nil,
			})
			if err == nil {
				t.Fatalf("NewIssuerFromFiles() error = nil, want error")
			}

			if internalIssuer != nil {
				t.Errorf("NewIssuerFromFiles() issuer = %v, want nil", internalIssuer)
			}

			if keys != nil {
				t.Errorf("NewIssuerFromFiles() key provider = %v, want nil", keys)
			}
		})
	}
}

func writePrivateKeyPEM(t *testing.T, path string, curve elliptic.Curve) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v, want nil", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: nil, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v, want nil", err)
	}
}

func writePublicKeyPEM(t *testing.T, path string, curve elliptic.Curve) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v, want nil", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v, want nil", err)
	}
}
