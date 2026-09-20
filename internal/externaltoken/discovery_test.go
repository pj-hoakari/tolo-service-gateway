package externaltoken_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/externaltoken"
)

const (
	openIDPath              = "/.well-known/openid-configuration"
	authorizationServerPath = "/.well-known/oauth-authorization-server"
)

type response struct {
	status int
	body   string
}

type metadataServer struct {
	mu        sync.Mutex
	responses map[string]response
	requested []string

	server *httptest.Server
}

func newMetadataServer(t *testing.T) *metadataServer {
	t.Helper()

	metadata := &metadataServer{
		responses: map[string]response{},
		requested: nil,
		server:    nil,
	}

	metadata.server = httptest.NewServer(http.HandlerFunc(metadata.serve))
	t.Cleanup(metadata.server.Close)

	return metadata
}

func (m *metadataServer) serve(writer http.ResponseWriter, request *http.Request) {
	m.mu.Lock()
	m.requested = append(m.requested, request.URL.Path)
	found, ok := m.responses[request.URL.Path]
	m.mu.Unlock()

	if !ok {
		http.NotFound(writer, request)

		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(found.status)
	_, _ = writer.Write([]byte(found.body))
}

func (m *metadataServer) set(path string, found response) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.responses[path] = found
}

func (m *metadataServer) paths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return slices.Clone(m.requested)
}

func metadataBody(t *testing.T, members map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	return string(encoded)
}

func TestDiscover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		documents         func(t *testing.T, issuer string) map[string]response
		wantJWKS          string
		wantIntrospection string
		wantErr           error
	}{
		{
			name: "both documents agree",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
					authorizationServerPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":                 issuer,
						"jwks_uri":               issuer + "/oauth2/jwks",
						"introspection_endpoint": issuer + "/oauth2/introspect",
					})},
				}
			},
			wantJWKS:          "/oauth2/jwks",
			wantIntrospection: "/oauth2/introspect",
			wantErr:           nil,
		},
		{
			name: "introspection endpoint is absent",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				body := metadataBody(t, map[string]any{
					"issuer":   issuer,
					"jwks_uri": issuer + "/oauth2/jwks",
				})

				return map[string]response{
					openIDPath:              {status: http.StatusOK, body: body},
					authorizationServerPath: {status: http.StatusOK, body: body},
				}
			},
			wantJWKS:          "/oauth2/jwks",
			wantIntrospection: "",
			wantErr:           nil,
		},
		{
			name: "issuer differs by a trailing slash",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				body := metadataBody(t, map[string]any{
					"issuer":   issuer + "/",
					"jwks_uri": issuer + "/oauth2/jwks",
				})

				return map[string]response{
					openIDPath:              {status: http.StatusOK, body: body},
					authorizationServerPath: {status: http.StatusOK, body: body},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
		{
			name: "authorization server metadata names another issuer",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
					authorizationServerPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   "https://evil.example.test",
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
		{
			name: "jwks_uri is missing",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				body := metadataBody(t, map[string]any{"issuer": issuer})

				return map[string]response{
					openIDPath:              {status: http.StatusOK, body: body},
					authorizationServerPath: {status: http.StatusOK, body: body},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
		{
			name: "jwks_uri differs between the documents",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
					authorizationServerPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/other/jwks",
					})},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
		{
			name: "jwks_uri is relative",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				body := metadataBody(t, map[string]any{
					"issuer":   issuer,
					"jwks_uri": "/oauth2/jwks",
				})

				return map[string]response{
					openIDPath:              {status: http.StatusOK, body: body},
					authorizationServerPath: {status: http.StatusOK, body: body},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
		{
			name: "introspection endpoint is relative",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
					authorizationServerPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":                 issuer,
						"jwks_uri":               issuer + "/oauth2/jwks",
						"introspection_endpoint": "/oauth2/introspect",
					})},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
		{
			name: "openid configuration redirects",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusFound, body: ""},
					authorizationServerPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrUnexpectedStatus,
		},
		{
			name: "authorization server metadata is missing",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrUnexpectedStatus,
		},
		{
			name: "openid configuration is larger than the limit",
			documents: func(t *testing.T, issuer string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: `{"padding":"` + strings.Repeat("a", 1<<20) + `"}`},
					authorizationServerPath: {status: http.StatusOK, body: metadataBody(t, map[string]any{
						"issuer":   issuer,
						"jwks_uri": issuer + "/oauth2/jwks",
					})},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrDocumentTooLarge,
		},
		{
			name: "openid configuration is not JSON",
			documents: func(t *testing.T, _ string) map[string]response {
				t.Helper()

				return map[string]response{
					openIDPath: {status: http.StatusOK, body: "not json"},
				}
			},
			wantJWKS:          "",
			wantIntrospection: "",
			wantErr:           externaltoken.ErrInvalidMetadata,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			metadata := newMetadataServer(t)
			issuer := metadata.server.URL

			for path, found := range test.documents(t, issuer) {
				metadata.set(path, found)
			}

			got, err := externaltoken.Discover(t.Context(), metadata.server.Client(), issuer)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Discover() error = %v, want %v", err, test.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Discover() error = %v, want nil", err)
			}

			if got.Issuer != issuer {
				t.Errorf("Discover() issuer = %q, want %q", got.Issuer, issuer)
			}

			if got.JWKSURI != issuer+test.wantJWKS {
				t.Errorf("Discover() jwks_uri = %q, want %q", got.JWKSURI, issuer+test.wantJWKS)
			}

			wantIntrospection := ""
			if test.wantIntrospection != "" {
				wantIntrospection = issuer + test.wantIntrospection
			}

			if got.IntrospectionEndpoint != wantIntrospection {
				t.Errorf("Discover() introspection_endpoint = %q, want %q", got.IntrospectionEndpoint, wantIntrospection)
			}
		})
	}
}

func TestDiscoverIssuerWithPath(t *testing.T) {
	t.Parallel()

	metadata := newMetadataServer(t)
	issuer := metadata.server.URL + "/auth"
	body := metadataBody(t, map[string]any{
		"issuer":   issuer,
		"jwks_uri": issuer + "/oauth2/jwks",
	})

	metadata.set("/auth"+openIDPath, response{status: http.StatusOK, body: body})
	metadata.set(authorizationServerPath+"/auth", response{status: http.StatusOK, body: body})

	got, err := externaltoken.Discover(t.Context(), metadata.server.Client(), issuer)
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	if got.JWKSURI != issuer+"/oauth2/jwks" {
		t.Errorf("Discover() jwks_uri = %q, want %q", got.JWKSURI, issuer+"/oauth2/jwks")
	}

	want := []string{"/auth" + openIDPath, authorizationServerPath + "/auth"}
	if paths := metadata.paths(); !slices.Equal(paths, want) {
		t.Errorf("Discover() requested %q, want %q", paths, want)
	}
}

func TestDiscoverDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://evil.example.test"+request.URL.Path, http.StatusFound)
	}))
	t.Cleanup(server.Close)

	_, err := externaltoken.Discover(t.Context(), nil, server.URL)
	if !errors.Is(err, externaltoken.ErrUnexpectedStatus) {
		t.Fatalf("Discover() error = %v, want %v", err, externaltoken.ErrUnexpectedStatus)
	}
}

func TestDiscoverRejectsInvalidIssuers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer string
	}{
		{name: "empty", issuer: ""},
		{name: "relative", issuer: "/auth"},
		{name: "no host", issuer: "https://"},
		{name: "unsupported scheme", issuer: "ftp://idp.example.test"},
		{name: "with query", issuer: "https://idp.example.test?tenant=1"},
		{name: "with fragment", issuer: "https://idp.example.test#top"},
		{name: "with userinfo", issuer: "https://user@idp.example.test"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := externaltoken.Discover(t.Context(), nil, test.issuer)
			if !errors.Is(err, externaltoken.ErrInvalidIssuer) {
				t.Fatalf("Discover() error = %v, want %v", err, externaltoken.ErrInvalidIssuer)
			}
		})
	}
}
