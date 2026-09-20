package externaltoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultIntrospectionCacheTTL   = 60 * time.Second
	DefaultIntrospectionTimeout    = 5 * time.Second
	DefaultIntrospectionMaxEntries = 10000
)

var (
	ErrIntrospectionUnavailable = errors.New("the IdP cannot be asked whether the token is active")
	ErrInvalidIntrospection     = errors.New("the introspection config is invalid")
)

type IntrospectorConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	CacheTTL     time.Duration
	Timeout      time.Duration
	MaxEntries   int
	Clock        func() time.Time
}

type introspectionResult struct {
	active bool
	expiry time.Time
}

type introspectionDocument struct {
	Active *bool  `json:"active"`
	JTI    string `json:"jti"`
}

type Introspector struct {
	endpoint     string
	clientID     string
	clientSecret string
	client       *http.Client
	cacheTTL     time.Duration
	timeout      time.Duration
	maxEntries   int
	now          func() time.Time

	group singleflight.Group

	mu      sync.Mutex
	results map[string]introspectionResult
}

func NewIntrospector(config IntrospectorConfig) (*Introspector, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || !isHTTPURL(parsed) {
		return nil, fmt.Errorf("%w: endpoint %q is not an absolute HTTP URL", ErrInvalidIntrospection, config.Endpoint)
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("%w: the client ID and its secret are both required", ErrInvalidIntrospection)
	}

	client := config.HTTPClient
	if client == nil {
		client = noRedirectClient
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	maxEntries := config.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultIntrospectionMaxEntries
	}

	return &Introspector{
		endpoint:     config.Endpoint,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		client:       client,
		cacheTTL:     orDefaultDuration(config.CacheTTL, DefaultIntrospectionCacheTTL),
		timeout:      orDefaultDuration(config.Timeout, DefaultIntrospectionTimeout),
		maxEntries:   maxEntries,
		now:          clock,
		group:        singleflight.Group{},
		mu:           sync.Mutex{},
		results:      make(map[string]introspectionResult),
	}, nil
}

func (i *Introspector) Active(ctx context.Context, token, jti string, expiresAt time.Time) (bool, error) {
	if token == "" || jti == "" {
		return false, fmt.Errorf("%w: the token and its jti are both required", ErrIntrospectionUnavailable)
	}

	if active, cached := i.cached(jti); cached {
		return active, nil
	}

	shared, err, _ := i.group.Do(jti, func() (any, error) {
		if active, cached := i.cached(jti); cached {
			return active, nil
		}

		active, err := i.introspect(ctx, token, jti)
		if err != nil {
			return false, err
		}

		i.store(jti, active, expiresAt)

		return active, nil
	})
	if err != nil {
		return false, err
	}

	active, ok := shared.(bool)
	if !ok {
		return false, fmt.Errorf("%w: the introspection result has an unexpected type", ErrIntrospectionUnavailable)
	}

	return active, nil
}

func (i *Introspector) cached(jti string) (bool, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	result, found := i.results[jti]
	if !found || !i.now().Before(result.expiry) {
		return false, false
	}

	return result.active, true
}

func (i *Introspector) store(jti string, active bool, expiresAt time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.now()

	expiry := now.Add(i.cacheTTL)
	if !expiresAt.IsZero() && expiresAt.Before(expiry) {
		expiry = expiresAt
	}

	i.results[jti] = introspectionResult{active: active, expiry: expiry}

	if len(i.results) > i.maxEntries {
		i.evict(now)
	}
}

func (i *Introspector) evict(now time.Time) {
	for key, result := range i.results {
		if !now.Before(result.expiry) {
			delete(i.results, key)
		}
	}

	excess := len(i.results) - i.maxEntries
	if excess <= 0 {
		return
	}

	keys := make([]string, 0, len(i.results))
	for key := range i.results {
		keys = append(keys, key)
	}

	slices.SortFunc(keys, func(left, right string) int {
		return i.results[left].expiry.Compare(i.results[right].expiry)
	})

	for _, key := range keys[:excess] {
		delete(i.results, key)
	}
}

func (i *Introspector) introspect(ctx context.Context, token, jti string) (bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}

	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, i.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("%w: %s: build the request", ErrIntrospectionUnavailable, i.endpoint)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(url.QueryEscape(i.clientID), url.QueryEscape(i.clientSecret))

	response, err := i.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("%w: %s: %w", ErrIntrospectionUnavailable, i.endpoint, err)
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.WarnContext(ctx, "closing the introspection response body failed",
				slog.String("url", i.endpoint),
				slog.String("error", err.Error()),
			)
		}
	}()

	document, err := i.readDocument(response)
	if err != nil {
		return false, err
	}

	if *document.Active && document.JTI != "" && document.JTI != jti {
		return false, fmt.Errorf("%w: %s: the response answers for another jti", ErrIntrospectionUnavailable, i.endpoint)
	}

	return *document.Active, nil
}

func (i *Introspector) readDocument(response *http.Response) (introspectionDocument, error) {
	var zero introspectionDocument

	if response.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("%w: %s: %s", ErrIntrospectionUnavailable, i.endpoint, response.Status)
	}

	encoded, err := io.ReadAll(io.LimitReader(response.Body, DefaultMaxDocumentSize+1))
	if err != nil {
		return zero, fmt.Errorf("%w: %s: read the response", ErrIntrospectionUnavailable, i.endpoint)
	}

	if int64(len(encoded)) > DefaultMaxDocumentSize {
		return zero, fmt.Errorf("%w: %s: the response is over %d bytes", ErrIntrospectionUnavailable, i.endpoint, DefaultMaxDocumentSize)
	}

	var document introspectionDocument

	if err := json.Unmarshal(encoded, &document); err != nil {
		return zero, fmt.Errorf("%w: %s: the response is not an introspection document", ErrIntrospectionUnavailable, i.endpoint)
	}

	if document.Active == nil {
		return zero, fmt.Errorf("%w: %s: the response has no boolean active member", ErrIntrospectionUnavailable, i.endpoint)
	}

	return document, nil
}
