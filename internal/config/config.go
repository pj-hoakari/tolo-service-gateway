package config

import (
	"errors"
	"fmt"
	"strings"
)

const defaultListenAddr = ":8080"

const (
	envListenAddr        = "SERVER_ADDR"
	envIssuerID          = "INTERNAL_JWT_ISSUER"
	envSigningKeyFile    = "INTERNAL_JWT_SIGNING_KEY_FILE"
	envSigningKeyID      = "INTERNAL_JWT_SIGNING_KEY_ID"
	envPublishedKeyFiles = "INTERNAL_JWT_PUBLISHED_KEY_FILES"
	envIDPIssuer         = "IDP_ISSUER"
)

const publishedKeySeparator = "="

type KeyFile struct {
	ID   string
	Path string
}

type Config struct {
	ListenAddr    string
	IssuerID      string
	SigningKey    KeyFile
	PublishedKeys []KeyFile
	IDPIssuer     string
}

func Load(getenv func(string) string) (Config, error) {
	listenAddr := getenv(envListenAddr)
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	issuerID := getenv(envIssuerID)
	signingKeyFile := getenv(envSigningKeyFile)
	signingKeyID := getenv(envSigningKeyID)
	idpIssuer := getenv(envIDPIssuer)

	var errs []error

	if issuerID == "" {
		errs = append(errs, missingEnvError(envIssuerID))
	}

	if signingKeyFile == "" {
		errs = append(errs, missingEnvError(envSigningKeyFile))
	}

	if signingKeyID == "" {
		errs = append(errs, missingEnvError(envSigningKeyID))
	}

	publishedKeys, err := parsePublishedKeys(getenv(envPublishedKeyFiles), signingKeyID)
	if err != nil {
		errs = append(errs, err)
	}

	if idpIssuer != "" && idpIssuer == issuerID {
		errs = append(errs, fmt.Errorf("%s must not be the same value as %s", envIDPIssuer, envIssuerID))
	}

	if err := errors.Join(errs...); err != nil {
		var zero Config

		return zero, err
	}

	return Config{
		ListenAddr:    listenAddr,
		IssuerID:      issuerID,
		SigningKey:    KeyFile{ID: signingKeyID, Path: signingKeyFile},
		PublishedKeys: publishedKeys,
		IDPIssuer:     idpIssuer,
	}, nil
}

func parsePublishedKeys(raw, signingKeyID string) ([]KeyFile, error) {
	if raw == "" {
		return nil, nil
	}

	entries := strings.Split(raw, ",")
	keyFiles := make([]KeyFile, 0, len(entries))
	seen := make(map[string]struct{}, len(entries)+1)

	if signingKeyID != "" {
		seen[signingKeyID] = struct{}{}
	}

	var errs []error

	for index, entry := range entries {
		keyFile, err := parsePublishedKey(entry, index)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if _, duplicate := seen[keyFile.ID]; duplicate {
			errs = append(errs, publishedKeyError(index, fmt.Sprintf("key ID %q is already used by another key", keyFile.ID)))

			continue
		}

		seen[keyFile.ID] = struct{}{}
		keyFiles = append(keyFiles, keyFile)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return keyFiles, nil
}

func parsePublishedKey(entry string, index int) (KeyFile, error) {
	var zero KeyFile

	keyID, path, found := strings.Cut(entry, publishedKeySeparator)
	if !found {
		return zero, publishedKeyError(index, fmt.Sprintf("%q is not in the kid%spath form", entry, publishedKeySeparator))
	}

	if keyID == "" {
		return zero, publishedKeyError(index, "the key ID is empty")
	}

	if path == "" {
		return zero, publishedKeyError(index, "the key file path is empty")
	}

	return KeyFile{ID: keyID, Path: path}, nil
}

func publishedKeyError(index int, reason string) error {
	return fmt.Errorf("%s entry %d: %s", envPublishedKeyFiles, index+1, reason)
}

func missingEnvError(key string) error {
	return fmt.Errorf("%s is required but not set", key)
}
