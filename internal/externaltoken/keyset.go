package externaltoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultCacheTTL        = 5 * time.Minute
	DefaultRefreshCooldown = 30 * time.Second
	DefaultFailureCooldown = 5 * time.Second
	DefaultFetchTimeout    = 5 * time.Second

	minimumRSAKeySize  = 2048
	p256CoordinateSize = 32
)

var (
	ErrMissingKeyID    = errors.New("token has no kid")
	ErrUnknownKeyID    = errors.New("the IdP JWKS has no key with this kid")
	ErrKeysUnavailable = errors.New("the IdP verification keys are unavailable")
	ErrInvalidJWKS     = errors.New("JWKS document is invalid")

	ErrInvalidJWKSURL = errors.New("JWKS URL is not an absolute HTTP URL")

	errFetchRequired = errors.New("JWKS fetch required")
	errUnusableKey   = errors.New("unusable JWKS key")
)

type KeySetConfig struct {
	URL             string
	HTTPClient      *http.Client
	CacheTTL        time.Duration
	RefreshCooldown time.Duration
	FailureCooldown time.Duration
	FetchTimeout    time.Duration
	MaxDocumentSize int64
	Clock           func() time.Time
}

type KeySet struct {
	url             string
	client          *http.Client
	cacheTTL        time.Duration
	refreshCooldown time.Duration
	failureCooldown time.Duration
	fetchTimeout    time.Duration
	maxDocumentSize int64
	now             func() time.Time

	group singleflight.Group

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey
	expiry      time.Time
	lastRefresh time.Time
	lastFailure time.Time
	lastError   error
}

func NewKeySet(config KeySetConfig) (*KeySet, error) {
	parsed, err := url.Parse(config.URL)
	if err != nil || !isHTTPURL(parsed) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidJWKSURL, config.URL)
	}

	client := config.HTTPClient
	if client == nil {
		client = noRedirectClient
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	return &KeySet{
		url:             config.URL,
		client:          client,
		cacheTTL:        orDefaultDuration(config.CacheTTL, DefaultCacheTTL),
		refreshCooldown: orDefaultDuration(config.RefreshCooldown, DefaultRefreshCooldown),
		failureCooldown: orDefaultDuration(config.FailureCooldown, DefaultFailureCooldown),
		fetchTimeout:    orDefaultDuration(config.FetchTimeout, DefaultFetchTimeout),
		maxDocumentSize: orDefaultSize(config.MaxDocumentSize, DefaultMaxDocumentSize),
		now:             clock,
		group:           singleflight.Group{},
		mu:              sync.Mutex{},
		keys:            make(map[string]crypto.PublicKey),
		expiry:          time.Time{},
		lastRefresh:     time.Time{},
		lastFailure:     time.Time{},
		lastError:       nil,
	}, nil
}

func (k *KeySet) Key(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	if keyID == "" {
		return nil, ErrMissingKeyID
	}

	key, err := k.cached(keyID)
	if !errors.Is(err, errFetchRequired) {
		return key, err
	}

	if err := k.fetch(ctx); err != nil {
		return nil, err
	}

	return k.lookup(keyID)
}

func (k *KeySet) cached(keyID string) (crypto.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()

	if now.Before(k.expiry) {
		if key, ok := k.keys[keyID]; ok {
			return key, nil
		}

		if now.Sub(k.lastRefresh) < k.refreshCooldown {
			return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
		}
	}

	if !k.lastFailure.IsZero() && now.Sub(k.lastFailure) < k.failureCooldown {
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, k.lastError)
	}

	return nil, errFetchRequired
}

func (k *KeySet) lookup(keyID string) (crypto.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key, ok := k.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
	}

	return key, nil
}

func (k *KeySet) fetch(ctx context.Context) error {
	_, err, _ := k.group.Do(k.url, func() (any, error) {
		return nil, k.refresh(ctx)
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}

	return nil
}

func (k *KeySet) refresh(ctx context.Context) error {
	keys, err := k.load(ctx)
	if err != nil {
		k.recordFailure(ctx, err)

		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()
	k.keys = keys
	k.expiry = now.Add(k.cacheTTL)
	k.lastRefresh = now
	k.lastFailure = time.Time{}
	k.lastError = nil

	return nil
}

func (k *KeySet) load(ctx context.Context) (map[string]crypto.PublicKey, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, k.fetchTimeout)
	defer cancel()

	encoded, err := fetchDocument(fetchCtx, k.client, k.url, k.maxDocumentSize)
	if err != nil {
		return nil, err
	}

	return parseJWKS(encoded)
}

func (k *KeySet) recordFailure(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}

	slog.WarnContext(ctx, "fetching the external IdP verification keys failed",
		slog.String("url", k.url),
		slog.String("error", err.Error()),
	)

	k.mu.Lock()
	defer k.mu.Unlock()

	k.lastFailure = k.now()
	k.lastError = err
}

type jwk struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Curve     string `json:"crv"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
	XPosition string `json:"x"`
	YPosition string `json:"y"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

func parseJWKS(encoded []byte) (map[string]crypto.PublicKey, error) {
	var document jwksDocument

	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidJWKS, err)
	}

	keys := make(map[string]crypto.PublicKey, len(document.Keys))

	for _, value := range document.Keys {
		key, err := value.publicKey()

		switch {
		case errors.Is(err, errUnusableKey):
			continue
		case err != nil:
			return nil, fmt.Errorf("%w: %w", ErrInvalidJWKS, err)
		}

		if value.KeyID == "" {
			return nil, fmt.Errorf("%w: a %s key has no kid", ErrInvalidJWKS, value.KeyType)
		}

		if _, duplicate := keys[value.KeyID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate kid %q", ErrInvalidJWKS, value.KeyID)
		}

		keys[value.KeyID] = key
	}

	return keys, nil
}

func (value jwk) publicKey() (crypto.PublicKey, error) {
	if value.Use != "" && value.Use != "sig" {
		return nil, errUnusableKey
	}

	switch value.KeyType {
	case "RSA":
		return value.rsaKey()
	case "EC":
		return value.ecdsaKey()
	default:
		return nil, errUnusableKey
	}
}

func (value jwk) rsaKey() (crypto.PublicKey, error) {
	modulus, err := value.integer("n", value.Modulus)
	if err != nil {
		return nil, err
	}

	exponent, err := value.integer("e", value.Exponent)
	if err != nil {
		return nil, err
	}

	if modulus.BitLen() < minimumRSAKeySize {
		return nil, errUnusableKey
	}

	if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > math.MaxInt32 {
		return nil, fmt.Errorf("kid %q: exponent e is out of range", value.KeyID)
	}

	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func (value jwk) ecdsaKey() (crypto.PublicKey, error) {
	if value.Curve != "P-256" {
		return nil, errUnusableKey
	}

	x, err := value.coordinate("x", value.XPosition)
	if err != nil {
		return nil, err
	}

	y, err := value.coordinate("y", value.YPosition)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y))
	if err != nil {
		return nil, fmt.Errorf("kid %q: %w", value.KeyID, err)
	}

	return key, nil
}

func (value jwk) integer(name, encoded string) (*big.Int, error) {
	decoded, err := value.member(name, encoded)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(decoded), nil
}

func (value jwk) coordinate(name, encoded string) ([]byte, error) {
	decoded, err := value.member(name, encoded)
	if err != nil {
		return nil, err
	}

	if len(decoded) != p256CoordinateSize {
		return nil, fmt.Errorf("kid %q: member %s is not %d bytes", value.KeyID, name, p256CoordinateSize)
	}

	return decoded, nil
}

func (value jwk) member(name, encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("kid %q: member %s is missing", value.KeyID, name)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("kid %q: member %s is not base64url", value.KeyID, name)
	}

	return decoded, nil
}

func orDefaultDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}

	return value
}

func orDefaultSize(value, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}

	return value
}
