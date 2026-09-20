package idp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
)

const (
	DefaultRetryDelay  = 5 * time.Second
	defaultHTTPTimeout = 10 * time.Second
)

var (
	ErrInvalidConfig = errors.New("idp: the provider config is invalid")
	ErrNotResolved   = errors.New("idp: the IdP metadata is not resolved yet")
)

var (
	_ authn.ExternalVerifier = (*Provider)(nil)
	_ authn.Introspector     = (*Provider)(nil)
)

type Config struct {
	Issuer                    string
	Audience                  string
	Algorithms                []string
	IntrospectionClientID     string
	IntrospectionClientSecret string
	HTTPClient                *http.Client
	RetryDelay                time.Duration
	Clock                     func() time.Time
}

type resolution struct {
	metadata     externaltoken.Metadata
	verifier     *externaltoken.Verifier
	introspector *externaltoken.Introspector
}

type Provider struct {
	issuer                    string
	audience                  string
	algorithms                []string
	introspectionClientID     string
	introspectionClientSecret string
	client                    *http.Client
	retryDelay                time.Duration
	clock                     func() time.Time
	resolved                  atomic.Pointer[resolution]
}

func New(config Config) (*Provider, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidConfig)
	}

	if config.Audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrInvalidConfig)
	}

	client := config.HTTPClient
	if client == nil {
		client = NewHTTPClient()
	}

	retryDelay := config.RetryDelay
	if retryDelay <= 0 {
		retryDelay = DefaultRetryDelay
	}

	if (config.IntrospectionClientID == "") != (config.IntrospectionClientSecret == "") {
		return nil, fmt.Errorf("%w: the introspection client ID and its secret are set together or not at all", ErrInvalidConfig)
	}

	return &Provider{
		issuer:                    config.Issuer,
		audience:                  config.Audience,
		algorithms:                slices.Clone(config.Algorithms),
		introspectionClientID:     config.IntrospectionClientID,
		introspectionClientSecret: config.IntrospectionClientSecret,
		client:                    client,
		retryDelay:                retryDelay,
		clock:                     config.Clock,
		resolved:                  atomic.Pointer[resolution]{},
	}, nil
}

func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (p *Provider) Run(ctx context.Context) error {
	for {
		metadata, err := externaltoken.Discover(ctx, p.client, p.issuer)
		if err == nil {
			return p.resolve(ctx, metadata)
		}

		if fatal(err) {
			return fmt.Errorf("discover the IdP metadata: %w", err)
		}

		if ctx.Err() == nil {
			slog.WarnContext(ctx, "resolving the IdP metadata failed; retrying",
				slog.String("issuer", p.issuer),
				slog.String("error", err.Error()),
				slog.Duration("retry_in", p.retryDelay),
			)
		}

		timer := time.NewTimer(p.retryDelay)

		select {
		case <-ctx.Done():
			timer.Stop()

			return nil
		case <-timer.C:
		}
	}
}

func (p *Provider) resolve(ctx context.Context, metadata externaltoken.Metadata) error {
	keys, err := externaltoken.NewKeySet(externaltoken.KeySetConfig{
		URL:             metadata.JWKSURI,
		HTTPClient:      p.client,
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    0,
		MaxDocumentSize: 0,
		Clock:           p.clock,
	})
	if err != nil {
		return fmt.Errorf("build the IdP key set: %w", err)
	}

	verifier, err := externaltoken.NewVerifier(externaltoken.Config{
		Issuer:     p.issuer,
		Audience:   p.audience,
		Algorithms: p.algorithms,
		Keys:       keys,
		Leeway:     0,
		Clock:      p.clock,
	})
	if err != nil {
		return fmt.Errorf("build the external token verifier: %w", err)
	}

	introspector, err := p.newIntrospector(metadata)
	if err != nil {
		return err
	}

	p.resolved.Store(&resolution{metadata: metadata, verifier: verifier, introspector: introspector})

	slog.InfoContext(ctx, "the IdP metadata is resolved",
		slog.String("issuer", metadata.Issuer),
		slog.Bool("introspection", introspector != nil),
	)

	return nil
}

func (p *Provider) newIntrospector(metadata externaltoken.Metadata) (*externaltoken.Introspector, error) {
	if p.introspectionClientID == "" {
		return nil, nil //nolint:nilnil // an unconfigured introspector is not a failure
	}

	if metadata.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("%w: the IdP metadata has no introspection_endpoint", ErrInvalidConfig)
	}

	introspector, err := externaltoken.NewIntrospector(externaltoken.IntrospectorConfig{
		Endpoint:     metadata.IntrospectionEndpoint,
		ClientID:     p.introspectionClientID,
		ClientSecret: p.introspectionClientSecret,
		HTTPClient:   p.client,
		CacheTTL:     0,
		Timeout:      0,
		MaxEntries:   0,
		Clock:        p.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("build the token introspector: %w", err)
	}

	return introspector, nil
}

func fatal(err error) bool {
	return errors.Is(err, externaltoken.ErrInvalidMetadata) ||
		errors.Is(err, externaltoken.ErrInvalidIssuer) ||
		errors.Is(err, externaltoken.ErrDocumentTooLarge)
}

func (p *Provider) Verify(ctx context.Context, token string) (authn.ExternalToken, error) {
	var zero authn.ExternalToken

	current := p.resolved.Load()
	if current == nil {
		return zero, fmt.Errorf("%w: %w", ErrNotResolved, authn.ErrVerifierUnavailable)
	}

	claims, err := current.verifier.Verify(ctx, token)
	if err != nil {
		if errors.Is(err, externaltoken.ErrKeysUnavailable) {
			return zero, fmt.Errorf("%w: %w", authn.ErrVerifierUnavailable, err)
		}

		return zero, fmt.Errorf("verify the external token: %w", err)
	}

	return authn.ExternalToken{
		Subject:           claims.Subject,
		ClientID:          claims.ClientID,
		TokenUse:          claims.TokenUse,
		Scope:             claims.Scope,
		JTI:               claims.JTI,
		TenantID:          claims.TenantID,
		EventID:           claims.EventID,
		ExpiresAt:         claims.ExpiresAt,
		SenderConstrained: claims.Confirmation != "",
	}, nil
}

func (p *Provider) Active(ctx context.Context, token string, verified authn.ExternalToken) (bool, error) {
	current := p.resolved.Load()
	if current == nil {
		return false, fmt.Errorf("%w: %w", externaltoken.ErrIntrospectionUnavailable, ErrNotResolved)
	}

	if current.introspector == nil {
		return false, fmt.Errorf("%w: introspection is not configured", externaltoken.ErrIntrospectionUnavailable)
	}

	active, err := current.introspector.Active(ctx, token, verified.JTI, verified.ExpiresAt)
	if err != nil {
		return false, fmt.Errorf("ask the IdP whether the token is active: %w", err)
	}

	return active, nil
}

func (p *Provider) Ready(_ context.Context) error {
	if p.resolved.Load() == nil {
		return ErrNotResolved
	}

	return nil
}

func (p *Provider) Metadata() (externaltoken.Metadata, bool) {
	current := p.resolved.Load()
	if current == nil {
		return externaltoken.Metadata{Issuer: "", JWKSURI: "", IntrospectionEndpoint: ""}, false
	}

	return current.metadata, true
}
