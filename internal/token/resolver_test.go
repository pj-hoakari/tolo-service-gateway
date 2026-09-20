package token_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"
	"testing"

	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"

	"github.com/pj-hoakari/tolo-service-gateway/internal/token"
)

var errKeyProviderDown = errors.New("key provider is down")

func TestLocalKeyResolverKey(t *testing.T) {
	t.Parallel()

	signingKey := newKey(t)
	rotatedKey := newKey(t)

	withSigningKey := signingProvider(
		localSigningKeyID,
		signingKey,
		issuer.PublishedKey{KeyID: localRotatedKeyID, Key: &rotatedKey.PublicKey},
	)

	withoutSigningKey := staticKeyProvider{
		keySet: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: localSigningKeyID, Key: nil},
			Published: []issuer.PublishedKey{{KeyID: localRotatedKeyID, Key: &rotatedKey.PublicKey}},
		},
		err: nil,
	}

	tests := map[string]struct {
		keys  issuer.KeyProvider
		keyID string
		want  *ecdsa.PublicKey
	}{
		"the signing key ID": {
			keys:  withSigningKey,
			keyID: localSigningKeyID,
			want:  &signingKey.PublicKey,
		},
		"a published key ID": {
			keys:  withSigningKey,
			keyID: localRotatedKeyID,
			want:  &rotatedKey.PublicKey,
		},
		"a published key ID while the key set holds no signing key": {
			keys:  withoutSigningKey,
			keyID: localRotatedKeyID,
			want:  &rotatedKey.PublicKey,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := token.NewLocalKeyResolver(tt.keys).Key(t.Context(), tt.keyID)
			if err != nil {
				t.Fatalf("Key() error = %v, want nil", err)
			}

			if !tt.want.Equal(got) {
				t.Errorf("Key() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalKeyResolverKeyRejects(t *testing.T) {
	t.Parallel()

	signingKey := newKey(t)
	rotatedKey := newKey(t)

	withSigningKey := signingProvider(
		localSigningKeyID,
		signingKey,
		issuer.PublishedKey{KeyID: localRotatedKeyID, Key: &rotatedKey.PublicKey},
	)

	withoutSigningKey := staticKeyProvider{
		keySet: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: localSigningKeyID, Key: nil},
			Published: []issuer.PublishedKey{{KeyID: localRotatedKeyID, Key: &rotatedKey.PublicKey}},
		},
		err: nil,
	}

	tests := map[string]struct {
		keys    issuer.KeyProvider
		keyID   string
		wantErr error
	}{
		"a key ID no key carries": {
			keys:    withSigningKey,
			keyID:   localForeignKeyID,
			wantErr: verifier.ErrUnknownKey,
		},
		"an empty key ID": {
			keys:    withSigningKey,
			keyID:   "",
			wantErr: verifier.ErrUnknownKey,
		},
		"the signing key ID while the key set holds no signing key": {
			keys:    withoutSigningKey,
			keyID:   localSigningKeyID,
			wantErr: verifier.ErrUnknownKey,
		},
		"a key provider that fails": {
			keys:    staticKeyProvider{keySet: issuer.KeySet{}, err: errKeyProviderDown},
			keyID:   localSigningKeyID,
			wantErr: errKeyProviderDown,
		},
		"a key provider that fails is told apart from an unknown key ID": {
			keys:    staticKeyProvider{keySet: issuer.KeySet{}, err: errKeyProviderDown},
			keyID:   localSigningKeyID,
			wantErr: token.ErrLoadKeys,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := token.NewLocalKeyResolver(tt.keys).Key(t.Context(), tt.keyID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Key() error = %v, want %v", err, tt.wantErr)
			}

			if got != nil {
				t.Errorf("Key() = %v, want nil", got)
			}
		})
	}
}

type rotatingKeyProvider struct {
	mu     sync.Mutex
	keySet issuer.KeySet
}

func (p *rotatingKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.keySet, nil
}

func (p *rotatingKeyProvider) replace(keySet issuer.KeySet) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.keySet = keySet
}

func TestLocalKeyResolverKeyFollowsARotation(t *testing.T) {
	t.Parallel()

	first := newKey(t)
	second := newKey(t)

	keys := &rotatingKeyProvider{
		mu: sync.Mutex{},
		keySet: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: localRotatedKeyID, Key: first},
			Published: nil,
		},
	}

	resolver := token.NewLocalKeyResolver(keys)
	ctx := t.Context()

	got, err := resolver.Key(ctx, localRotatedKeyID)
	if err != nil {
		t.Fatalf("Key() error = %v, want nil", err)
	}

	if !first.PublicKey.Equal(got) {
		t.Errorf("Key() = %v, want the first key", got)
	}

	keys.replace(issuer.KeySet{
		Signing:   issuer.SigningKey{KeyID: localSigningKeyID, Key: second},
		Published: []issuer.PublishedKey{{KeyID: localRotatedKeyID, Key: &first.PublicKey}},
	})

	got, err = resolver.Key(ctx, localSigningKeyID)
	if err != nil {
		t.Fatalf("Key() error = %v, want nil", err)
	}

	if !second.PublicKey.Equal(got) {
		t.Errorf("Key() = %v, want the second key", got)
	}
}
