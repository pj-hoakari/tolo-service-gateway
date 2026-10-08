package config_test

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/config"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env                  map[string]string
		wantErr              bool
		wantErrContains      []string
		wantIssuerID         string
		wantSigningKey       config.KeyFile
		wantPublishedKeys    []config.KeyFile
		wantIDPIssuer        string
		wantDestinationsFile string
	}{
		"all values set": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/next.pub.pem",
				"IDP_ISSUER":                       "https://idp.example.com",
				"IDP_AUDIENCE":                     "backend-api",
				"IDP_INTROSPECTION":                "disabled",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantIssuerID:    "service-gateway",
			wantSigningKey:  config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys: []config.KeyFile{
				{ID: "next-key", Path: "/etc/tolo/keys/next.pub.pem"},
			},
			wantIDPIssuer:        "https://idp.example.com",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"only the required values set": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              false,
			wantErrContains:      nil,
			wantIssuerID:         "service-gateway",
			wantSigningKey:       config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"values are not trimmed": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              " service-gateway ",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    " /etc/tolo/signing-key.pem ",
				"INTERNAL_JWT_SIGNING_KEY_ID":      " dev-key-1 ",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": " next-key = /etc/tolo/keys/next.pub.pem ",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantIssuerID:    " service-gateway ",
			wantSigningKey:  config.KeyFile{ID: " dev-key-1 ", Path: " /etc/tolo/signing-key.pem "},
			wantPublishedKeys: []config.KeyFile{
				{ID: " next-key ", Path: " /etc/tolo/keys/next.pub.pem "},
			},
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"empty published key files is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              false,
			wantErrContains:      nil,
			wantIssuerID:         "service-gateway",
			wantSigningKey:       config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"several published key files": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/next.pub.pem,old-key=/etc/tolo/keys/old.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantIssuerID:    "service-gateway",
			wantSigningKey:  config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys: []config.KeyFile{
				{ID: "next-key", Path: "/etc/tolo/keys/next.pub.pem"},
				{ID: "old-key", Path: "/etc/tolo/keys/old.pub.pem"},
			},
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"a published key path may contain an equals sign": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/a=b.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantIssuerID:    "service-gateway",
			wantSigningKey:  config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys: []config.KeyFile{
				{ID: "next-key", Path: "/etc/tolo/keys/a=b.pub.pem"},
			},
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"an IdP issuer that differs from the internal issuer is accepted": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"IDP_ISSUER":                     "https://idp.example.com",
				"IDP_AUDIENCE":                   "backend-api",
				"IDP_INTROSPECTION":              "disabled",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              false,
			wantErrContains:      nil,
			wantIssuerID:         "service-gateway",
			wantSigningKey:       config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "https://idp.example.com",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"missing issuer": {
			env: map[string]string{
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_ISSUER"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"empty issuer is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_ISSUER"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"missing signing key file": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_SIGNING_KEY_FILE"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"empty signing key file is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_SIGNING_KEY_FILE"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"missing signing key id": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_SIGNING_KEY_ID"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"empty signing key id is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_SIGNING_KEY_ID"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"missing destinations file": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":           "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE": "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":   "dev-key-1",
			},
			wantErr:              true,
			wantErrContains:      []string{"TOLO_GATEWAY_DESTINATIONS_FILE"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"empty destinations file is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "",
			},
			wantErr:              true,
			wantErrContains:      []string{"TOLO_GATEWAY_DESTINATIONS_FILE"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"every required value missing": {
			env:     map[string]string{},
			wantErr: true,
			wantErrContains: []string{
				"INTERNAL_JWT_ISSUER",
				"INTERNAL_JWT_SIGNING_KEY_FILE",
				"INTERNAL_JWT_SIGNING_KEY_ID",
				"TOLO_GATEWAY_DESTINATIONS_FILE",
			},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"a published key entry without a separator": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "/etc/tolo/keys/next.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "entry 1"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"a published key entry with an empty key id": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "=/etc/tolo/keys/next.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "key ID"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"a published key entry with an empty path": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "key file path"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"a trailing comma leaves an empty published key entry": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/next.pub.pem,",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "entry 2"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"repeated commas leave an empty published key entry": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/next.pub.pem,,old-key=/etc/tolo/keys/old.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "entry 2"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"two published keys share a key id": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/next.pub.pem,next-key=/etc/tolo/keys/old.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "next-key"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"a published key reuses the signing key id": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "dev-key-1=/etc/tolo/keys/next.pub.pem",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"INTERNAL_JWT_PUBLISHED_KEY_FILES", "dev-key-1"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
		"the IdP issuer is the internal issuer": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"IDP_ISSUER":                     "service-gateway",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              true,
			wantErrContains:      []string{"IDP_ISSUER", "INTERNAL_JWT_ISSUER"},
			wantIssuerID:         "",
			wantSigningKey:       config.KeyFile{ID: "", Path: ""},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(withPublicListener(tt.env))

			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want error")
				}

				for _, want := range tt.wantErrContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Load() error = %q, want it to mention %q", err.Error(), want)
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.IssuerID; got != tt.wantIssuerID {
				t.Errorf("IssuerID = %q, want %q", got, tt.wantIssuerID)
			}

			if got := cfg.SigningKey; got != tt.wantSigningKey {
				t.Errorf("SigningKey = %+v, want %+v", got, tt.wantSigningKey)
			}

			if got := cfg.PublishedKeys; !slices.Equal(got, tt.wantPublishedKeys) {
				t.Errorf("PublishedKeys = %+v, want %+v", got, tt.wantPublishedKeys)
			}

			if got := cfg.IDPIssuer; got != tt.wantIDPIssuer {
				t.Errorf("IDPIssuer = %q, want %q", got, tt.wantIDPIssuer)
			}

			if got := cfg.DestinationsFile; got != tt.wantDestinationsFile {
				t.Errorf("DestinationsFile = %q, want %q", got, tt.wantDestinationsFile)
			}
		})
	}
}

func TestLoadIDP(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuer          string
		audience        string
		algorithms      string
		wantAlgorithms  []string
		wantErrContains string
	}{
		"nothing set": {
			issuer:          "",
			audience:        "",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "",
		},
		"the issuer and the audience": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  []string{"RS256"},
			wantErrContains: "",
		},
		"an issuer with a path": {
			issuer:          "https://idp.example.com/tenants/tolo",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  []string{"RS256"},
			wantErrContains: "",
		},
		"both algorithms": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "ES256,RS256",
			wantAlgorithms:  []string{"ES256", "RS256"},
			wantErrContains: "",
		},
		"one algorithm": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "ES256",
			wantAlgorithms:  []string{"ES256"},
			wantErrContains: "",
		},
		"the issuer without the audience": {
			issuer:          "https://idp.example.com",
			audience:        "",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_AUDIENCE",
		},
		"the audience without the issuer": {
			issuer:          "",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_AUDIENCE",
		},
		"the algorithms without the issuer": {
			issuer:          "",
			audience:        "",
			algorithms:      "RS256",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ALGORITHMS",
		},
		"an unsupported algorithm": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "RS256,HS256",
			wantAlgorithms:  nil,
			wantErrContains: "HS256",
		},
		"a duplicated algorithm": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "RS256,RS256",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ALGORITHMS",
		},
		"an empty algorithm": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "RS256,",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ALGORITHMS",
		},
		"algorithms surrounded by spaces": {
			issuer:          "https://idp.example.com",
			audience:        "backend-api",
			algorithms:      "RS256, ES256",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ALGORITHMS",
		},
		"an issuer that is not a URL": {
			issuer:          "idp.example.com",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ISSUER",
		},
		"an issuer with another scheme": {
			issuer:          "ftp://idp.example.com",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ISSUER",
		},
		"an issuer with a query": {
			issuer:          "https://idp.example.com?tenant=tolo",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ISSUER",
		},
		"an issuer with a fragment": {
			issuer:          "https://idp.example.com#tolo",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ISSUER",
		},
		"an issuer with userinfo": {
			issuer:          "https://user@idp.example.com",
			audience:        "backend-api",
			algorithms:      "",
			wantAlgorithms:  nil,
			wantErrContains: "IDP_ISSUER",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(withPublicListener(map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
				"IDP_ISSUER":                     tt.issuer,
				"IDP_AUDIENCE":                   tt.audience,
				"IDP_ALGORITHMS":                 tt.algorithms,
				"IDP_INTROSPECTION":              idpIntrospectionFor(tt.issuer),
			}))

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("Load() error = nil, want it to mention %q", tt.wantErrContains)
				}

				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("Load() error = %q, want it to mention %q", err.Error(), tt.wantErrContains)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.IDPIssuer; got != tt.issuer {
				t.Errorf("IDPIssuer = %q, want %q", got, tt.issuer)
			}

			if got := cfg.IDPAudience; got != tt.audience {
				t.Errorf("IDPAudience = %q, want %q", got, tt.audience)
			}

			if got := cfg.IDPAlgorithms; !slices.Equal(got, tt.wantAlgorithms) {
				t.Errorf("IDPAlgorithms = %v, want %v", got, tt.wantAlgorithms)
			}
		})
	}
}

func TestLoadTrustedProxyHops(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		raw     string
		want    int
		wantErr bool
	}{
		"unset":                {raw: "", want: 0, wantErr: false},
		"zero":                 {raw: "0", want: 0, wantErr: false},
		"one":                  {raw: "1", want: 1, wantErr: false},
		"the highest hop":      {raw: "16", want: 16, wantErr: false},
		"above the range":      {raw: "17", want: 0, wantErr: true},
		"below the range":      {raw: "-1", want: 0, wantErr: true},
		"not a number":         {raw: "two", want: 0, wantErr: true},
		"not an integer":       {raw: "1.5", want: 0, wantErr: true},
		"surrounded by spaces": {raw: " 1 ", want: 0, wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(withPublicListener(map[string]string{
				"INTERNAL_JWT_ISSUER":             "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":   "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":     "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE":  "/etc/tolo/gateway/destinations.json",
				"TOLO_GATEWAY_TRUSTED_PROXY_HOPS": tt.raw,
			}))

			if tt.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want error")
				}

				if !strings.Contains(err.Error(), "TOLO_GATEWAY_TRUSTED_PROXY_HOPS") {
					t.Errorf("Load() error = %q, want it to mention %q", err.Error(), "TOLO_GATEWAY_TRUSTED_PROXY_HOPS")
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.TrustedProxyHops; got != tt.want {
				t.Errorf("TrustedProxyHops = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLoadIntrospection(t *testing.T) {
	t.Parallel()

	const credential = "introspection-client-credential"

	secretFile := writeSecretFile(t, credential+"\n")

	tests := map[string]struct {
		issuer          string
		introspection   string
		clientID        string
		secretFile      string
		wantClientID    string
		wantSecret      string
		wantDisabled    bool
		wantErrContains string
	}{
		"both values set": {
			issuer:          "https://idp.example.com",
			introspection:   "",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "gateway-introspection",
			wantSecret:      credential,
			wantDisabled:    false,
			wantErrContains: "",
		},
		"both values set and introspection required": {
			issuer:          "https://idp.example.com",
			introspection:   "required",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "gateway-introspection",
			wantSecret:      credential,
			wantDisabled:    false,
			wantErrContains: "",
		},
		"nothing set": {
			issuer:          "https://idp.example.com",
			introspection:   "",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION",
		},
		"nothing set and introspection required": {
			issuer:          "https://idp.example.com",
			introspection:   "required",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION",
		},
		"nothing set and introspection disabled": {
			issuer:          "https://idp.example.com",
			introspection:   "disabled",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    true,
			wantErrContains: "",
		},
		"both values set and introspection disabled": {
			issuer:          "https://idp.example.com",
			introspection:   "disabled",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION",
		},
		"another case is not accepted": {
			issuer:          "https://idp.example.com",
			introspection:   "Required",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION",
		},
		"true is not accepted": {
			issuer:          "https://idp.example.com",
			introspection:   "true",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION",
		},
		"surrounded by spaces": {
			issuer:          "https://idp.example.com",
			introspection:   " disabled ",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION",
		},
		"the mode without the issuer": {
			issuer:          "",
			introspection:   "disabled",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_ISSUER",
		},
		"neither the issuer nor anything else": {
			issuer:          "",
			introspection:   "",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "",
		},
		"the client ID without the secret file": {
			issuer:          "https://idp.example.com",
			introspection:   "",
			clientID:        "gateway-introspection",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION_CLIENT_SECRET_FILE",
		},
		"the secret file without the client ID": {
			issuer:          "https://idp.example.com",
			introspection:   "",
			clientID:        "",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION_CLIENT_ID",
		},
		"introspection without the issuer": {
			issuer:          "",
			introspection:   "",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_ISSUER",
		},
		"a secret file that does not exist": {
			issuer:          "https://idp.example.com",
			introspection:   "",
			clientID:        "gateway-introspection",
			secretFile:      t.TempDir() + "/absent",
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION_CLIENT_SECRET_FILE",
		},
		"an empty secret file": {
			issuer:          "https://idp.example.com",
			introspection:   "",
			clientID:        "gateway-introspection",
			secretFile:      writeSecretFile(t, "\n"),
			wantClientID:    "",
			wantSecret:      "",
			wantDisabled:    false,
			wantErrContains: "IDP_INTROSPECTION_CLIENT_SECRET_FILE",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(withPublicListener(map[string]string{
				"INTERNAL_JWT_ISSUER":                  "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":        "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":          "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE":       "/etc/tolo/gateway/destinations.json",
				"IDP_ISSUER":                           tt.issuer,
				"IDP_AUDIENCE":                         idpAudienceFor(tt.issuer),
				"IDP_INTROSPECTION":                    tt.introspection,
				"IDP_INTROSPECTION_CLIENT_ID":          tt.clientID,
				"IDP_INTROSPECTION_CLIENT_SECRET_FILE": tt.secretFile,
			}))

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("Load() error = nil, want error")
				}

				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("Load() error = %q, want it to mention %q", err.Error(), tt.wantErrContains)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.IDPIntrospectionClientID; got != tt.wantClientID {
				t.Errorf("IDPIntrospectionClientID = %q, want %q", got, tt.wantClientID)
			}

			if got := cfg.IDPIntrospectionSecret; got != tt.wantSecret {
				t.Errorf("IDPIntrospectionSecret = %q, want the value the file holds", got)
			}

			if got := cfg.IDPIntrospectionSecretFile; got != tt.secretFile {
				t.Errorf("IDPIntrospectionSecretFile = %q, want %q", got, tt.secretFile)
			}

			if got := cfg.IDPIntrospectionDisabled; got != tt.wantDisabled {
				t.Errorf("IDPIntrospectionDisabled = %v, want %v", got, tt.wantDisabled)
			}
		})
	}
}

func TestLoadTrimsTheSecretFile(t *testing.T) {
	t.Parallel()

	const credential = "introspection-client-credential"

	tests := map[string]string{
		"without a trailing newline": credential,
		"with a trailing newline":    credential + "\n",
		"with a CRLF line ending":    credential + "\r\n",
		"with several newlines":      credential + "\n\n",
	}

	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			secretFile := writeSecretFile(t, content)

			cfg, err := config.Load(withPublicListener(map[string]string{
				"INTERNAL_JWT_ISSUER":                  "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":        "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":          "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE":       "/etc/tolo/gateway/destinations.json",
				"IDP_ISSUER":                           "https://idp.example.com",
				"IDP_AUDIENCE":                         "backend-api",
				"IDP_INTROSPECTION_CLIENT_ID":          "gateway-introspection",
				"IDP_INTROSPECTION_CLIENT_SECRET_FILE": secretFile,
			}))
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.IDPIntrospectionSecret; got != credential {
				t.Errorf("IDPIntrospectionSecret = %q, want the line the file holds", got)
			}
		})
	}
}

func TestLoadLegacyEventsWriteScope(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		issuer          string
		raw             string
		want            bool
		wantErrContains string
	}{
		"unset": {
			issuer:          "https://idp.example.com",
			raw:             "",
			want:            false,
			wantErrContains: "",
		},
		"enabled": {
			issuer:          "https://idp.example.com",
			raw:             "enabled",
			want:            true,
			wantErrContains: "",
		},
		"true is not accepted": {
			issuer:          "https://idp.example.com",
			raw:             "true",
			want:            false,
			wantErrContains: "IDP_LEGACY_EVENTS_WRITE_SCOPE",
		},
		"one is not accepted": {
			issuer:          "https://idp.example.com",
			raw:             "1",
			want:            false,
			wantErrContains: "IDP_LEGACY_EVENTS_WRITE_SCOPE",
		},
		"another case is not accepted": {
			issuer:          "https://idp.example.com",
			raw:             "Enabled",
			want:            false,
			wantErrContains: "IDP_LEGACY_EVENTS_WRITE_SCOPE",
		},
		"surrounded by spaces": {
			issuer:          "https://idp.example.com",
			raw:             " enabled ",
			want:            false,
			wantErrContains: "IDP_LEGACY_EVENTS_WRITE_SCOPE",
		},
		"disabled is not accepted": {
			issuer:          "https://idp.example.com",
			raw:             "disabled",
			want:            false,
			wantErrContains: "IDP_LEGACY_EVENTS_WRITE_SCOPE",
		},
		"without the issuer": {
			issuer:          "",
			raw:             "enabled",
			want:            false,
			wantErrContains: "IDP_ISSUER",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(withPublicListener(map[string]string{
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
				"IDP_ISSUER":                     tt.issuer,
				"IDP_AUDIENCE":                   idpAudienceFor(tt.issuer),
				"IDP_INTROSPECTION":              idpIntrospectionFor(tt.issuer),
				"IDP_LEGACY_EVENTS_WRITE_SCOPE":  tt.raw,
			}))

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("Load() error = nil, want it to mention %q", tt.wantErrContains)
				}

				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("Load() error = %q, want it to mention %q", err.Error(), tt.wantErrContains)
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.IDPLegacyEventsWriteScope; got != tt.want {
				t.Errorf("IDPLegacyEventsWriteScope = %v, want %v", got, tt.want)
			}
		})
	}
}

func writeSecretFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "introspection-client-secret")

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v, want nil", err)
	}

	return path
}

func idpAudienceFor(issuer string) string {
	if issuer == "" {
		return ""
	}

	return "backend-api"
}

func idpIntrospectionFor(issuer string) string {
	if issuer == "" {
		return ""
	}

	return "disabled"
}

func requiredEnv() map[string]string {
	return map[string]string{
		"INTERNAL_JWT_ISSUER":            "service-gateway",
		"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
		"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
		"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
	}
}

func withPublicListener(env map[string]string) func(string) string {
	listener := map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "8080"}

	return func(key string) string {
		if value, ok := env[key]; ok {
			return value
		}

		return listener[key]
	}
}

func TestLoadListeners(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env             map[string]string
		wantMode        string
		wantListeners   []config.Listener
		wantErrContains []string
	}{
		"split": {
			env: map[string]string{
				"TOLO_GATEWAY_LISTENER_MODE": "split",
				"TOLO_GATEWAY_PUBLIC_PORT":   "8080",
				"TOLO_GATEWAY_INTERNAL_PORT": "8090",
			},
			wantMode: "split",
			wantListeners: []config.Listener{
				{Inbound: config.InboundPublic, Addr: ":8080"},
				{Inbound: config.InboundInternal, Addr: ":8090"},
			},
		},
		"public": {
			env:           map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "8080"},
			wantMode:      "public",
			wantListeners: []config.Listener{{Inbound: config.InboundPublic, Addr: ":8080"}},
		},
		"internal": {
			env:           map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "internal", "PORT": "65535"},
			wantMode:      "internal",
			wantListeners: []config.Listener{{Inbound: config.InboundInternal, Addr: ":65535"}},
		},
		"split ignores PORT": {
			env: map[string]string{
				"TOLO_GATEWAY_LISTENER_MODE": "split",
				"TOLO_GATEWAY_PUBLIC_PORT":   "1",
				"TOLO_GATEWAY_INTERNAL_PORT": "2",
				"PORT":                       "8080",
			},
			wantMode: "split",
			wantListeners: []config.Listener{
				{Inbound: config.InboundPublic, Addr: ":1"},
				{Inbound: config.InboundInternal, Addr: ":2"},
			},
		},
		"no mode": {
			env:             map[string]string{"PORT": "8080"},
			wantErrContains: []string{"TOLO_GATEWAY_LISTENER_MODE"},
		},
		"empty mode": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "", "PORT": "8080"},
			wantErrContains: []string{"TOLO_GATEWAY_LISTENER_MODE"},
		},
		"a mode in another case": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "Public", "PORT": "8080"},
			wantErrContains: []string{"TOLO_GATEWAY_LISTENER_MODE", `"Public"`},
		},
		"an unknown mode": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "both", "PORT": "8080"},
			wantErrContains: []string{"TOLO_GATEWAY_LISTENER_MODE", `"both"`},
		},
		"split without ports": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "split", "PORT": "8080"},
			wantErrContains: []string{"TOLO_GATEWAY_PUBLIC_PORT", "TOLO_GATEWAY_INTERNAL_PORT"},
		},
		"split without the internal port": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "split", "TOLO_GATEWAY_PUBLIC_PORT": "8080"},
			wantErrContains: []string{"TOLO_GATEWAY_INTERNAL_PORT"},
		},
		"split on one port": {
			env: map[string]string{
				"TOLO_GATEWAY_LISTENER_MODE": "split",
				"TOLO_GATEWAY_PUBLIC_PORT":   "8080",
				"TOLO_GATEWAY_INTERNAL_PORT": "8080",
			},
			wantErrContains: []string{"TOLO_GATEWAY_PUBLIC_PORT", "TOLO_GATEWAY_INTERNAL_PORT", "differ"},
		},
		"public without PORT": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public"},
			wantErrContains: []string{"PORT"},
		},
		"internal without PORT": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "internal"},
			wantErrContains: []string{"PORT"},
		},
		"public with a split port": {
			env: map[string]string{
				"TOLO_GATEWAY_LISTENER_MODE": "public",
				"PORT":                       "8080",
				"TOLO_GATEWAY_PUBLIC_PORT":   "8080",
			},
			wantErrContains: []string{"TOLO_GATEWAY_PUBLIC_PORT"},
		},
		"internal with a split port": {
			env: map[string]string{
				"TOLO_GATEWAY_LISTENER_MODE": "internal",
				"PORT":                       "8090",
				"TOLO_GATEWAY_INTERNAL_PORT": "8090",
			},
			wantErrContains: []string{"TOLO_GATEWAY_INTERNAL_PORT"},
		},
		"port zero": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "0"},
			wantErrContains: []string{"PORT", `"0"`},
		},
		"port above the range": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "65536"},
			wantErrContains: []string{"PORT", `"65536"`},
		},
		"port with a sign": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "+8080"},
			wantErrContains: []string{"PORT"},
		},
		"port with a leading zero": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "08080"},
			wantErrContains: []string{"PORT"},
		},
		"port with spaces": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": " 8080"},
			wantErrContains: []string{"PORT"},
		},
		"an address instead of a port": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": ":8080"},
			wantErrContains: []string{"PORT"},
		},
		"a split port out of range": {
			env: map[string]string{
				"TOLO_GATEWAY_LISTENER_MODE": "split",
				"TOLO_GATEWAY_PUBLIC_PORT":   "8080",
				"TOLO_GATEWAY_INTERNAL_PORT": "70000",
			},
			wantErrContains: []string{"TOLO_GATEWAY_INTERNAL_PORT"},
		},
		"SERVER_ADDR": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "8080", "SERVER_ADDR": ":8080"},
			wantErrContains: []string{"SERVER_ADDR"},
		},
		"TOLO_WORKLOAD_AUTH_MODE": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "public", "PORT": "8080", "TOLO_WORKLOAD_AUTH_MODE": "none"},
			wantErrContains: []string{"TOLO_WORKLOAD_AUTH_MODE"},
		},
		"TOLO_GATEWAY_ROLE": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "split", "TOLO_GATEWAY_PUBLIC_PORT": "8080", "TOLO_GATEWAY_INTERNAL_PORT": "8090", "TOLO_GATEWAY_ROLE": "public"},
			wantErrContains: []string{"TOLO_GATEWAY_ROLE"},
		},
		"TOLO_GATEWAY_WORKLOAD_PORT": {
			env:             map[string]string{"TOLO_GATEWAY_LISTENER_MODE": "internal", "PORT": "8090", "TOLO_GATEWAY_WORKLOAD_PORT": "8091"},
			wantErrContains: []string{"TOLO_GATEWAY_WORKLOAD_PORT"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := requiredEnv()
			maps.Copy(env, tt.env)

			cfg, err := config.Load(func(key string) string { return env[key] })

			if tt.wantErrContains != nil {
				if err == nil {
					t.Fatalf("Load() error = nil, want error")
				}

				for _, want := range tt.wantErrContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Load() error = %q, want it to mention %s", err.Error(), want)
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}

			if got := cfg.ListenerMode; got != tt.wantMode {
				t.Errorf("ListenerMode = %q, want %q", got, tt.wantMode)
			}

			if got := cfg.Listeners; !slices.Equal(got, tt.wantListeners) {
				t.Errorf("Listeners = %+v, want %+v", got, tt.wantListeners)
			}
		})
	}
}
