package externaltoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

const DefaultLeeway = 30 * time.Second

var (
	ErrInvalidConfig = errors.New("external token verifier config is invalid")
	ErrInvalidToken  = errors.New("external token is invalid")
	ErrInvalidClaims = errors.New("external token claims are invalid")
)

var (
	supportedAlgorithms = []string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodES256.Alg()}
	publicIDPattern     = regexp.MustCompile(`^[0-9a-f]{16}$`)
	externalTokenUses   = []string{
		internaljwt.TokenUseTenantAccess,
		internaljwt.TokenUseEventAccess,
		internaljwt.TokenUseRegistration,
	}
)

var _ KeyResolver = (*KeySet)(nil)

type KeyResolver interface {
	Key(ctx context.Context, keyID string) (crypto.PublicKey, error)
}

type Claims struct {
	Subject      string
	ClientID     string
	TokenUse     string
	Scope        string
	JTI          string
	TenantID     string
	EventID      string
	ExpiresAt    time.Time
	Confirmation string
}

type Config struct {
	Issuer     string
	Audience   string
	Algorithms []string
	Keys       KeyResolver
	Leeway     time.Duration
	Clock      func() time.Time
}

type Verifier struct {
	parser   *jwt.Parser
	keys     KeyResolver
	audience string
}

func NewVerifier(config Config) (*Verifier, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidConfig)
	}

	if config.Audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrInvalidConfig)
	}

	if config.Keys == nil {
		return nil, fmt.Errorf("%w: key resolver is required", ErrInvalidConfig)
	}

	algorithms := config.Algorithms
	if len(algorithms) == 0 {
		algorithms = []string{jwt.SigningMethodRS256.Alg()}
	}

	for _, algorithm := range algorithms {
		if !slices.Contains(supportedAlgorithms, algorithm) {
			return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidConfig, algorithm)
		}
	}

	leeway := config.Leeway
	if leeway <= 0 {
		leeway = DefaultLeeway
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods(slices.Clone(algorithms)),
		jwt.WithIssuer(config.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
	}

	if config.Clock != nil {
		options = append(options, jwt.WithTimeFunc(config.Clock))
	}

	return &Verifier{
		parser:   jwt.NewParser(options...),
		keys:     config.Keys,
		audience: config.Audience,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	claims := jwt.MapClaims{}

	if _, err := v.parser.ParseWithClaims(token, claims, v.keyFunc(ctx)); err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			return Claims{}, fmt.Errorf("resolve the external token verification key: %w", err)
		}

		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if err := v.checkAudience(claims); err != nil {
		return Claims{}, err
	}

	return readClaims(claims)
}

func (v *Verifier) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok || keyID == "" {
			return nil, ErrMissingKeyID
		}

		key, err := v.keys.Key(ctx, keyID)
		if err != nil {
			return nil, err
		}

		if err := checkKeyAlgorithm(key, token.Method.Alg()); err != nil {
			return nil, err
		}

		return key, nil
	}
}

func checkKeyAlgorithm(key crypto.PublicKey, algorithm string) error {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		if algorithm == jwt.SigningMethodRS256.Alg() {
			return nil
		}
	case *ecdsa.PublicKey:
		if algorithm == jwt.SigningMethodES256.Alg() && typed.Curve == elliptic.P256() {
			return nil
		}
	}

	return fmt.Errorf("%w: alg %q does not match the verification key", ErrInvalidToken, algorithm)
}

func (v *Verifier) checkAudience(claims jwt.MapClaims) error {
	audience, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("%w: aud: %w", ErrInvalidClaims, err)
	}

	if len(audience) != 1 {
		return fmt.Errorf("%w: aud must hold exactly one value, got %d", ErrInvalidClaims, len(audience))
	}

	if audience[0] != v.audience {
		return fmt.Errorf("%w: aud is %q, want %q", ErrInvalidClaims, audience[0], v.audience)
	}

	return nil
}

func readClaims(claims jwt.MapClaims) (Claims, error) {
	subject, err := stringClaim(claims, "sub")
	if err != nil {
		return Claims{}, err
	}

	clientID, err := stringClaim(claims, "client_id")
	if err != nil {
		return Claims{}, err
	}

	scope, err := stringClaim(claims, "scope")
	if err != nil {
		return Claims{}, err
	}

	tokenID, err := stringClaim(claims, "jti")
	if err != nil {
		return Claims{}, err
	}

	tokenUse, err := readTokenUse(claims)
	if err != nil {
		return Claims{}, err
	}

	tenantID, eventID, err := readBinding(claims, tokenUse)
	if err != nil {
		return Claims{}, err
	}

	confirmation, err := readConfirmation(claims)
	if err != nil {
		return Claims{}, err
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return Claims{}, fmt.Errorf("%w: exp is missing", ErrInvalidClaims)
	}

	return Claims{
		Subject:      subject,
		ClientID:     clientID,
		TokenUse:     tokenUse,
		Scope:        scope,
		JTI:          tokenID,
		TenantID:     tenantID,
		EventID:      eventID,
		ExpiresAt:    expiresAt.UTC(),
		Confirmation: confirmation,
	}, nil
}

func readTokenUse(claims jwt.MapClaims) (string, error) {
	tokenUse, err := stringClaim(claims, "token_use")
	if err != nil {
		return "", err
	}

	if !slices.Contains(externalTokenUses, tokenUse) {
		return "", fmt.Errorf("%w: token_use %q is not an external token use", ErrInvalidClaims, tokenUse)
	}

	return tokenUse, nil
}

func readBinding(claims jwt.MapClaims, tokenUse string) (string, string, error) {
	tenantID, err := publicIDClaim(claims, "tenant_id")
	if err != nil {
		return "", "", err
	}

	eventID, err := publicIDClaim(claims, "event_id")
	if err != nil {
		return "", "", err
	}

	if err := internaljwt.ValidateBinding(tokenUse, tenantID, eventID); err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}

	return tenantID, eventID, nil
}

func readConfirmation(claims jwt.MapClaims) (string, error) {
	value, present := claims["cnf"]
	if !present {
		return "", nil
	}

	confirmation, ok := value.(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: cnf is not an object", ErrInvalidClaims)
	}

	thumbprint, ok := confirmation["jkt"].(string)
	if !ok || thumbprint == "" {
		return "", fmt.Errorf("%w: cnf.jkt is not a non-empty string", ErrInvalidClaims)
	}

	return thumbprint, nil
}

func publicIDClaim(claims jwt.MapClaims, name string) (string, error) {
	value, present := claims[name]
	if !present {
		return "", nil
	}

	publicID, ok := value.(string)
	if !ok || !publicIDPattern.MatchString(publicID) {
		return "", fmt.Errorf("%w: %s is not a 16 digit lowercase hex public ID", ErrInvalidClaims, name)
	}

	return publicID, nil
}

func stringClaim(claims jwt.MapClaims, name string) (string, error) {
	value, present := claims[name]
	if !present {
		return "", fmt.Errorf("%w: %s is missing", ErrInvalidClaims, name)
	}

	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("%w: %s is not a non-empty string", ErrInvalidClaims, name)
	}

	return text, nil
}
