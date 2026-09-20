package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

const defaultListenAddr = ":8080"

const maxTrustedProxyHops = 16

const (
	envListenAddr        = "SERVER_ADDR"
	envIssuerID          = "INTERNAL_JWT_ISSUER"
	envSigningKeyFile    = "INTERNAL_JWT_SIGNING_KEY_FILE"
	envSigningKeyID      = "INTERNAL_JWT_SIGNING_KEY_ID"
	envPublishedKeyFiles = "INTERNAL_JWT_PUBLISHED_KEY_FILES"
	envIDPIssuer         = "IDP_ISSUER"
	envIDPAudience       = "IDP_AUDIENCE"
	envIDPAlgorithms     = "IDP_ALGORITHMS"
	envDestinationsFile  = "TOLO_GATEWAY_DESTINATIONS_FILE"
	envTrustedProxyHops  = "TOLO_GATEWAY_TRUSTED_PROXY_HOPS"

	envIDPIntrospectionClientID   = "IDP_INTROSPECTION_CLIENT_ID"
	envIDPIntrospectionSecretFile = "IDP_INTROSPECTION_CLIENT_SECRET_FILE" //nolint:gosec // the name of an environment variable holding a path, not a credential

	envIDPLegacyEventsWriteScope = "IDP_LEGACY_EVENTS_WRITE_SCOPE"
)

const legacyEventsWriteScopeEnabled = "enabled"

const publishedKeySeparator = "="

const algorithmSeparator = ","

var supportedIDPAlgorithms = []string{"RS256", "ES256"}

var defaultIDPAlgorithms = []string{"RS256"}

type KeyFile struct {
	ID   string
	Path string
}

type Config struct {
	ListenAddr                 string
	IssuerID                   string
	SigningKey                 KeyFile
	PublishedKeys              []KeyFile
	IDPIssuer                  string
	IDPAudience                string
	IDPAlgorithms              []string
	IDPIntrospectionClientID   string
	IDPIntrospectionSecretFile string
	IDPIntrospectionSecret     string
	IDPLegacyEventsWriteScope  bool
	DestinationsFile           string
	TrustedProxyHops           int
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
	destinationsFile := getenv(envDestinationsFile)

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

	if destinationsFile == "" {
		errs = append(errs, missingEnvError(envDestinationsFile))
	}

	publishedKeys, err := parsePublishedKeys(getenv(envPublishedKeyFiles), signingKeyID)
	if err != nil {
		errs = append(errs, err)
	}

	trustedProxyHops, err := parseTrustedProxyHops(getenv(envTrustedProxyHops))
	if err != nil {
		errs = append(errs, err)
	}

	if idpIssuer != "" && idpIssuer == issuerID {
		errs = append(errs, fmt.Errorf("%s must not be the same value as %s", envIDPIssuer, envIssuerID))
	}

	idpAudience := getenv(envIDPAudience)

	idpAlgorithms, err := parseIDP(idpIssuer, idpAudience, getenv(envIDPAlgorithms))
	if err != nil {
		errs = append(errs, err)
	}

	introspectionClientID := getenv(envIDPIntrospectionClientID)
	introspectionSecretFile := getenv(envIDPIntrospectionSecretFile)

	introspectionSecret, err := loadIntrospectionSecret(idpIssuer, introspectionClientID, introspectionSecretFile)
	if err != nil {
		errs = append(errs, err)
	}

	legacyEventsWriteScope, err := parseLegacyEventsWriteScope(idpIssuer, getenv(envIDPLegacyEventsWriteScope))
	if err != nil {
		errs = append(errs, err)
	}

	if err := errors.Join(errs...); err != nil {
		var zero Config

		return zero, err
	}

	return Config{
		ListenAddr:                 listenAddr,
		IssuerID:                   issuerID,
		SigningKey:                 KeyFile{ID: signingKeyID, Path: signingKeyFile},
		PublishedKeys:              publishedKeys,
		IDPIssuer:                  idpIssuer,
		IDPAudience:                idpAudience,
		IDPAlgorithms:              idpAlgorithms,
		IDPIntrospectionClientID:   introspectionClientID,
		IDPIntrospectionSecretFile: introspectionSecretFile,
		IDPIntrospectionSecret:     introspectionSecret,
		IDPLegacyEventsWriteScope:  legacyEventsWriteScope,
		DestinationsFile:           destinationsFile,
		TrustedProxyHops:           trustedProxyHops,
	}, nil
}

func loadIntrospectionSecret(issuer, clientID, secretFile string) (string, error) {
	if clientID == "" && secretFile == "" {
		return "", nil
	}

	var errs []error

	if clientID == "" {
		errs = append(errs, fmt.Errorf("%s is set but %s is not", envIDPIntrospectionSecretFile, envIDPIntrospectionClientID))
	}

	if secretFile == "" {
		errs = append(errs, fmt.Errorf("%s is set but %s is not", envIDPIntrospectionClientID, envIDPIntrospectionSecretFile))
	}

	if issuer == "" {
		errs = append(errs, fmt.Errorf("introspection is configured but %s is not set", envIDPIssuer))
	}

	if err := errors.Join(errs...); err != nil {
		return "", err
	}

	secret, err := readSecretFile(secretFile)
	if err != nil {
		return "", err
	}

	return secret, nil
}

func parseLegacyEventsWriteScope(issuer, raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}

	if raw != legacyEventsWriteScopeEnabled {
		return false, fmt.Errorf("%s must be %q when it is set, got %q", envIDPLegacyEventsWriteScope, legacyEventsWriteScopeEnabled, raw)
	}

	if issuer == "" {
		return false, fmt.Errorf("%s is set but %s is not", envIDPLegacyEventsWriteScope, envIDPIssuer)
	}

	return true, nil
}

func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is operator configuration read once at startup, never request input
	if err != nil {
		return "", fmt.Errorf("%s: read %s: %w", envIDPIntrospectionSecretFile, path, err)
	}

	secret := strings.TrimRight(string(raw), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("%s: %s holds no secret", envIDPIntrospectionSecretFile, path)
	}

	return secret, nil
}

func parseIDP(issuer, audience, algorithms string) ([]string, error) {
	if issuer == "" {
		var errs []error

		if audience != "" {
			errs = append(errs, fmt.Errorf("%s is set but %s is not", envIDPAudience, envIDPIssuer))
		}

		if algorithms != "" {
			errs = append(errs, fmt.Errorf("%s is set but %s is not", envIDPAlgorithms, envIDPIssuer))
		}

		return nil, errors.Join(errs...)
	}

	var errs []error

	if err := checkIDPIssuer(issuer); err != nil {
		errs = append(errs, err)
	}

	if audience == "" {
		errs = append(errs, fmt.Errorf("%s is required when %s is set", envIDPAudience, envIDPIssuer))
	}

	parsed, err := parseIDPAlgorithms(algorithms)
	if err != nil {
		errs = append(errs, err)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return parsed, nil
}

func checkIDPIssuer(issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%s must be an absolute HTTP URL, got %q: %w", envIDPIssuer, issuer, err)
	}

	usable := (parsed.Scheme == "http" || parsed.Scheme == "https") &&
		parsed.Host != "" &&
		parsed.Opaque == "" &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		parsed.User == nil

	if !usable {
		return fmt.Errorf("%s must be an absolute HTTP URL without userinfo, query or fragment, got %q", envIDPIssuer, issuer)
	}

	return nil
}

func parseIDPAlgorithms(raw string) ([]string, error) {
	if raw == "" {
		return slices.Clone(defaultIDPAlgorithms), nil
	}

	entries := strings.Split(raw, algorithmSeparator)
	algorithms := make([]string, 0, len(entries))

	var errs []error

	for _, entry := range entries {
		switch {
		case !slices.Contains(supportedIDPAlgorithms, entry):
			errs = append(errs, fmt.Errorf("%s: %q is not one of %s", envIDPAlgorithms, entry, strings.Join(supportedIDPAlgorithms, ", ")))
		case slices.Contains(algorithms, entry):
			errs = append(errs, fmt.Errorf("%s: %q appears more than once", envIDPAlgorithms, entry))
		default:
			algorithms = append(algorithms, entry)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return algorithms, nil
}

func parseTrustedProxyHops(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}

	hops, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer between 0 and %d, got %q", envTrustedProxyHops, maxTrustedProxyHops, raw)
	}

	if hops < 0 || hops > maxTrustedProxyHops {
		return 0, fmt.Errorf("%s must be between 0 and %d, got %d", envTrustedProxyHops, maxTrustedProxyHops, hops)
	}

	return hops, nil
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
