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
	"strings"
)

const (
	openIDConfigurationPath       = "/.well-known/openid-configuration"
	authorizationServerPath       = "/.well-known/oauth-authorization-server"
	DefaultMaxDocumentSize  int64 = 1 << 20
)

var (
	ErrInvalidIssuer    = errors.New("issuer is not an absolute HTTP URL")
	ErrFetch            = errors.New("fetch document")
	ErrUnexpectedStatus = errors.New("unexpected response status")
	ErrDocumentTooLarge = errors.New("document is too large")
	ErrInvalidMetadata  = errors.New("provider metadata is invalid")
)

type unexpectedStatusError struct {
	documentURL string
	status      string
	code        int
}

func (e *unexpectedStatusError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrUnexpectedStatus.Error(), e.documentURL, e.status)
}

func (e *unexpectedStatusError) Unwrap() error {
	return ErrUnexpectedStatus
}

type Metadata struct {
	Issuer                string
	JWKSURI               string
	IntrospectionEndpoint string
}

type metadataDocument struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

var noRedirectClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func Discover(ctx context.Context, httpClient *http.Client, issuer string) (Metadata, error) {
	base, err := parseIssuer(issuer)
	if err != nil {
		return Metadata{}, err
	}

	if httpClient == nil {
		httpClient = noRedirectClient
	}

	openID, err := fetchMetadata(ctx, httpClient, openIDConfigurationURL(base))
	if err != nil {
		return Metadata{}, err
	}

	authorizationServer, err := fetchMetadata(ctx, httpClient, authorizationServerURL(base))
	if err != nil {
		return Metadata{}, err
	}

	if err := checkMetadata(issuer, openID, authorizationServer); err != nil {
		return Metadata{}, err
	}

	return Metadata{
		Issuer:                issuer,
		JWKSURI:               openID.JWKSURI,
		IntrospectionEndpoint: authorizationServer.IntrospectionEndpoint,
	}, nil
}

func checkMetadata(issuer string, openID, authorizationServer metadataDocument) error {
	if err := checkDocument(issuer, "openid-configuration", openID); err != nil {
		return err
	}

	if err := checkDocument(issuer, "oauth-authorization-server", authorizationServer); err != nil {
		return err
	}

	if openID.JWKSURI != authorizationServer.JWKSURI {
		return fmt.Errorf("%w: jwks_uri differs between the two documents: %q and %q",
			ErrInvalidMetadata, openID.JWKSURI, authorizationServer.JWKSURI)
	}

	if authorizationServer.IntrospectionEndpoint == "" {
		return nil
	}

	return checkEndpoint("introspection_endpoint", authorizationServer.IntrospectionEndpoint)
}

func checkDocument(issuer, name string, document metadataDocument) error {
	if document.Issuer != issuer {
		return fmt.Errorf("%w: %s declares issuer %q, want %q", ErrInvalidMetadata, name, document.Issuer, issuer)
	}

	return checkEndpoint(name+" jwks_uri", document.JWKSURI)
}

func checkEndpoint(name, raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: %s is missing", ErrInvalidMetadata, name)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %s %q: %w", ErrInvalidMetadata, name, raw, err)
	}

	if !isHTTPURL(parsed) {
		return fmt.Errorf("%w: %s %q is not an absolute HTTP URL", ErrInvalidMetadata, name, raw)
	}

	return nil
}

func parseIssuer(issuer string) (*url.URL, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidIssuer, issuer, err)
	}

	if !isHTTPURL(parsed) || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidIssuer, issuer)
	}

	return parsed, nil
}

func isHTTPURL(parsed *url.URL) bool {
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.Opaque == ""
}

func openIDConfigurationURL(base *url.URL) string {
	return base.Scheme + "://" + base.Host + strings.TrimSuffix(base.EscapedPath(), "/") + openIDConfigurationPath
}

func authorizationServerURL(base *url.URL) string {
	return base.Scheme + "://" + base.Host + authorizationServerPath + strings.TrimSuffix(base.EscapedPath(), "/")
}

func fetchMetadata(ctx context.Context, client *http.Client, documentURL string) (metadataDocument, error) {
	encoded, err := fetchDocument(ctx, client, documentURL, DefaultMaxDocumentSize)
	if err != nil {
		return metadataDocument{}, err
	}

	var document metadataDocument

	if err := json.Unmarshal(encoded, &document); err != nil {
		return metadataDocument{}, fmt.Errorf("%w: %s: %w", ErrInvalidMetadata, documentURL, err)
	}

	return document, nil
}

func fetchDocument(ctx context.Context, client *http.Client, documentURL string, maxSize int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFetch, documentURL, err)
	}

	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFetch, documentURL, err)
	}

	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.WarnContext(ctx, "closing the fetched document body failed",
				slog.String("url", documentURL),
				slog.String("error", err.Error()),
			)
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, &unexpectedStatusError{
			documentURL: documentURL,
			status:      response.Status,
			code:        response.StatusCode,
		}
	}

	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFetch, documentURL, err)
	}

	if int64(len(encoded)) > maxSize {
		return nil, fmt.Errorf("%w: %s: over %d bytes", ErrDocumentTooLarge, documentURL, maxSize)
	}

	return encoded, nil
}
