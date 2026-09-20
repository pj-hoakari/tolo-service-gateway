package token

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

var ErrLoadKeys = errors.New("load internal JWT keys")

var _ verifier.KeyResolver = (*LocalKeyResolver)(nil)

type LocalKeyResolver struct {
	keys issuer.KeyProvider
}

func NewLocalKeyResolver(keys issuer.KeyProvider) *LocalKeyResolver {
	return &LocalKeyResolver{keys: keys}
}

func (r *LocalKeyResolver) Key(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	keySet, err := r.keys.Current(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadKeys, err)
	}

	if keySet.Signing.Key != nil && keySet.Signing.KeyID == keyID {
		return &keySet.Signing.Key.PublicKey, nil
	}

	for _, published := range keySet.Published {
		if published.KeyID == keyID {
			return published.Key, nil
		}
	}

	return nil, fmt.Errorf("%w: %q", verifier.ErrUnknownKey, keyID)
}
