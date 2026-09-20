package token

import (
	"fmt"

	"github.com/pj-hoakari/internal-jwt-handling/issuer"
)

type FileKeys struct {
	Signing   issuer.KeyFile
	Published []issuer.KeyFile
}

func NewIssuerFromFiles(issuerID string, keys FileKeys) (*issuer.Issuer, issuer.KeyProvider, error) {
	provider, err := issuer.NewFileKeyProvider(issuer.FileKeyProviderConfig{
		Signing:         keys.Signing,
		Published:       keys.Published,
		RefreshInterval: 0,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read internal JWT key files: %w", err)
	}

	internalIssuer, err := issuer.New(issuerID, provider)
	if err != nil {
		return nil, nil, fmt.Errorf("create internal JWT issuer: %w", err)
	}

	return internalIssuer, provider, nil
}
