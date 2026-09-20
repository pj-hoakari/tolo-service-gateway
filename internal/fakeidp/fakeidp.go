package fakeidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	JWKSPath                = "/oauth2/jwks"
	IntrospectionPath       = "/oauth2/introspect"
	TokenPath               = "/token"
	openIDConfigurationPath = "/.well-known/openid-configuration"
	authorizationServerPath = "/.well-known/oauth-authorization-server"
)

const (
	keyID             = "fake-idp-1"
	keySize           = 2048
	defaultTTL        = 5 * time.Minute
	maxRequestSize    = 1 << 16
	tokenIDByteLength = 16
)

var ErrInvalidConfig = errors.New("fakeidp: the config is invalid")

type Config struct {
	Issuer   string
	Audience string
}

type tokenRequest struct {
	TokenUse   string `json:"token_use"`
	Subject    string `json:"sub"`
	ClientID   string `json:"client_id"`
	Scope      string `json:"scope"`
	TenantID   string `json:"tenant_id"`
	EventID    string `json:"event_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type provider struct {
	issuer   string
	audience string
	key      *rsa.PrivateKey
}

func NewHandler(config Config) (http.Handler, error) {
	if err := checkIssuer(config.Issuer); err != nil {
		return nil, err
	}

	if config.Audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrInvalidConfig)
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("generate the signing key: %w", err)
	}

	idp := &provider{issuer: config.Issuer, audience: config.Audience, key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+openIDConfigurationPath, idp.handleMetadata)
	mux.HandleFunc("GET "+authorizationServerPath, idp.handleMetadata)
	mux.HandleFunc("GET "+JWKSPath, idp.handleJWKS)
	mux.HandleFunc("POST "+TokenPath, idp.handleToken)

	return mux, nil
}

func checkIssuer(issuer string) error {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("%w: issuer %q: %w", ErrInvalidConfig, issuer, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%w: issuer %q is not an absolute HTTP URL", ErrInvalidConfig, issuer)
	}

	return nil
}

func (p *provider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, map[string]any{
		"issuer":                                p.issuer,
		"jwks_uri":                              p.issuer + JWKSPath,
		"introspection_endpoint":                p.issuer + IntrospectionPath,
		"token_endpoint":                        p.issuer + TokenPath,
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{jwt.SigningMethodRS256.Alg()},
	})
}

func (p *provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	public := p.key.PublicKey

	writeJSON(w, r, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": jwt.SigningMethodRS256.Alg(),
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
}

func (p *provider) handleToken(w http.ResponseWriter, r *http.Request) {
	var request tokenRequest

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "the request body is not a token request", http.StatusBadRequest)

		return
	}

	signed, err := p.sign(request)
	if err != nil {
		slog.ErrorContext(r.Context(), "signing the development token failed", "error", err)
		http.Error(w, "signing the token failed", http.StatusInternalServerError)

		return
	}

	writeJSON(w, r, map[string]any{"access_token": signed, "token_type": "Bearer"})
}

func (p *provider) sign(request tokenRequest) (string, error) {
	tokenID, err := newTokenID()
	if err != nil {
		return "", err
	}

	ttl := defaultTTL
	if request.TTLSeconds > 0 {
		ttl = time.Duration(request.TTLSeconds) * time.Second
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       p.issuer,
		"aud":       p.audience,
		"sub":       request.Subject,
		"client_id": request.ClientID,
		"token_use": request.TokenUse,
		"scope":     request.Scope,
		"jti":       tokenID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
	}

	if request.TenantID != "" {
		claims["tenant_id"] = request.TenantID
	}

	if request.EventID != "" {
		claims["event_id"] = request.EventID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(p.key)
	if err != nil {
		return "", fmt.Errorf("sign the token: %w", err)
	}

	return signed, nil
}

func newTokenID() (string, error) {
	raw := make([]byte, tokenIDByteLength)

	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	return hex.EncodeToString(raw), nil
}

func writeJSON(w http.ResponseWriter, r *http.Request, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.ErrorContext(r.Context(), "writing the fake IdP response failed", "error", err)
	}
}
