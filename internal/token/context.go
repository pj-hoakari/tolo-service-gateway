package token

import (
	"fmt"

	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

func NewContextVerifier(issuerID string, keys issuer.KeyProvider) (*verifier.ContextVerifier, error) {
	if keys == nil {
		return nil, verifier.ErrMissingKeyResolver
	}

	contextVerifier, err := verifier.NewContextVerifier(issuerID, NewLocalKeyResolver(keys))
	if err != nil {
		return nil, fmt.Errorf("create context token verifier: %w", err)
	}

	return contextVerifier, nil
}
