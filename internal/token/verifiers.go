package token

import (
	"context"
	"errors"
	"fmt"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
)

var (
	ErrEmptyServiceID     = errors.New("service ID must not be empty")
	ErrDuplicateServiceID = errors.New("duplicate service ID")
	ErrUnknownService     = errors.New("unknown service ID")
)

type ContextVerifiers struct {
	byService map[string]*verifier.Verifier
}

func NewContextVerifiers(issuerID string, serviceIDs []string, keys verifier.KeyResolver) (*ContextVerifiers, error) {
	if issuerID == "" {
		return nil, verifier.ErrMissingIssuerID
	}

	byService := make(map[string]*verifier.Verifier, len(serviceIDs))

	for _, serviceID := range serviceIDs {
		if serviceID == "" {
			return nil, ErrEmptyServiceID
		}

		if _, duplicate := byService[serviceID]; duplicate {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateServiceID, serviceID)
		}

		contextVerifier, err := verifier.New(issuerID, serviceID, keys)
		if err != nil {
			return nil, fmt.Errorf("create context token verifier for %q: %w", serviceID, err)
		}

		byService[serviceID] = contextVerifier
	}

	return &ContextVerifiers{byService: byService}, nil
}

func (v *ContextVerifiers) Verify(ctx context.Context, presenterServiceID, token string) (internaljwt.Claims, error) {
	contextVerifier, ok := v.byService[presenterServiceID]
	if !ok {
		return internaljwt.Claims{}, fmt.Errorf("%w: %q", ErrUnknownService, presenterServiceID)
	}

	return contextVerifier.Verify(ctx, token)
}
