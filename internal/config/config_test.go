package config_test

import (
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
		wantListenAddr       string
		wantIssuerID         string
		wantSigningKey       config.KeyFile
		wantPublishedKeys    []config.KeyFile
		wantIDPIssuer        string
		wantDestinationsFile string
	}{
		"all values set": {
			env: map[string]string{
				"SERVER_ADDR":                      "127.0.0.1:9000",
				"INTERNAL_JWT_ISSUER":              "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":      "dev-key-1",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": "next-key=/etc/tolo/keys/next.pub.pem",
				"IDP_ISSUER":                       "https://idp.example.com",
				"IDP_AUDIENCE":                     "backend-api",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantListenAddr:  "127.0.0.1:9000",
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
			wantListenAddr:       ":8080",
			wantIssuerID:         "service-gateway",
			wantSigningKey:       config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"empty listen address falls back to the default": {
			env: map[string]string{
				"SERVER_ADDR":                    "",
				"INTERNAL_JWT_ISSUER":            "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
				"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              false,
			wantErrContains:      nil,
			wantListenAddr:       ":8080",
			wantIssuerID:         "service-gateway",
			wantSigningKey:       config.KeyFile{ID: "dev-key-1", Path: "/etc/tolo/signing-key.pem"},
			wantPublishedKeys:    nil,
			wantIDPIssuer:        "",
			wantDestinationsFile: "/etc/tolo/gateway/destinations.json",
		},
		"values are not trimmed": {
			env: map[string]string{
				"SERVER_ADDR":                      " :8081 ",
				"INTERNAL_JWT_ISSUER":              " service-gateway ",
				"INTERNAL_JWT_SIGNING_KEY_FILE":    " /etc/tolo/signing-key.pem ",
				"INTERNAL_JWT_SIGNING_KEY_ID":      " dev-key-1 ",
				"INTERNAL_JWT_PUBLISHED_KEY_FILES": " next-key = /etc/tolo/keys/next.pub.pem ",
				"TOLO_GATEWAY_DESTINATIONS_FILE":   "/etc/tolo/gateway/destinations.json",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantListenAddr:  " :8081 ",
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
			wantListenAddr:       ":8080",
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
			wantListenAddr:  ":8080",
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
			wantListenAddr:  ":8080",
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
				"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
			},
			wantErr:              false,
			wantErrContains:      nil,
			wantListenAddr:       ":8080",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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
			wantListenAddr:       "",
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

			cfg, err := config.Load(func(key string) string {
				return tt.env[key]
			})

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

			if got := cfg.ListenAddr; got != tt.wantListenAddr {
				t.Errorf("ListenAddr = %q, want %q", got, tt.wantListenAddr)
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

			cfg, err := config.Load(func(key string) string {
				return map[string]string{
					"INTERNAL_JWT_ISSUER":            "service-gateway",
					"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
					"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
					"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
					"IDP_ISSUER":                     tt.issuer,
					"IDP_AUDIENCE":                   tt.audience,
					"IDP_ALGORITHMS":                 tt.algorithms,
				}[key]
			})

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

			cfg, err := config.Load(func(key string) string {
				return map[string]string{
					"INTERNAL_JWT_ISSUER":             "service-gateway",
					"INTERNAL_JWT_SIGNING_KEY_FILE":   "/etc/tolo/signing-key.pem",
					"INTERNAL_JWT_SIGNING_KEY_ID":     "dev-key-1",
					"TOLO_GATEWAY_DESTINATIONS_FILE":  "/etc/tolo/gateway/destinations.json",
					"TOLO_GATEWAY_TRUSTED_PROXY_HOPS": tt.raw,
				}[key]
			})

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
		clientID        string
		secretFile      string
		wantClientID    string
		wantSecret      string
		wantErrContains string
	}{
		"nothing set": {
			issuer:          "https://idp.example.com",
			clientID:        "",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantErrContains: "",
		},
		"both values set": {
			issuer:          "https://idp.example.com",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "gateway-introspection",
			wantSecret:      credential,
			wantErrContains: "",
		},
		"the client ID without the secret file": {
			issuer:          "https://idp.example.com",
			clientID:        "gateway-introspection",
			secretFile:      "",
			wantClientID:    "",
			wantSecret:      "",
			wantErrContains: "IDP_INTROSPECTION_CLIENT_SECRET_FILE",
		},
		"the secret file without the client ID": {
			issuer:          "https://idp.example.com",
			clientID:        "",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantErrContains: "IDP_INTROSPECTION_CLIENT_ID",
		},
		"introspection without the issuer": {
			issuer:          "",
			clientID:        "gateway-introspection",
			secretFile:      secretFile,
			wantClientID:    "",
			wantSecret:      "",
			wantErrContains: "IDP_ISSUER",
		},
		"a secret file that does not exist": {
			issuer:          "https://idp.example.com",
			clientID:        "gateway-introspection",
			secretFile:      t.TempDir() + "/absent",
			wantClientID:    "",
			wantSecret:      "",
			wantErrContains: "IDP_INTROSPECTION_CLIENT_SECRET_FILE",
		},
		"an empty secret file": {
			issuer:          "https://idp.example.com",
			clientID:        "gateway-introspection",
			secretFile:      writeSecretFile(t, "\n"),
			wantClientID:    "",
			wantSecret:      "",
			wantErrContains: "IDP_INTROSPECTION_CLIENT_SECRET_FILE",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load(func(key string) string {
				return map[string]string{
					"INTERNAL_JWT_ISSUER":                  "service-gateway",
					"INTERNAL_JWT_SIGNING_KEY_FILE":        "/etc/tolo/signing-key.pem",
					"INTERNAL_JWT_SIGNING_KEY_ID":          "dev-key-1",
					"TOLO_GATEWAY_DESTINATIONS_FILE":       "/etc/tolo/gateway/destinations.json",
					"IDP_ISSUER":                           tt.issuer,
					"IDP_AUDIENCE":                         idpAudienceFor(tt.issuer),
					"IDP_INTROSPECTION_CLIENT_ID":          tt.clientID,
					"IDP_INTROSPECTION_CLIENT_SECRET_FILE": tt.secretFile,
				}[key]
			})

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

			cfg, err := config.Load(func(key string) string {
				return map[string]string{
					"INTERNAL_JWT_ISSUER":                  "service-gateway",
					"INTERNAL_JWT_SIGNING_KEY_FILE":        "/etc/tolo/signing-key.pem",
					"INTERNAL_JWT_SIGNING_KEY_ID":          "dev-key-1",
					"TOLO_GATEWAY_DESTINATIONS_FILE":       "/etc/tolo/gateway/destinations.json",
					"IDP_ISSUER":                           "https://idp.example.com",
					"IDP_AUDIENCE":                         "backend-api",
					"IDP_INTROSPECTION_CLIENT_ID":          "gateway-introspection",
					"IDP_INTROSPECTION_CLIENT_SECRET_FILE": secretFile,
				}[key]
			})
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

			cfg, err := config.Load(func(key string) string {
				return map[string]string{
					"INTERNAL_JWT_ISSUER":            "service-gateway",
					"INTERNAL_JWT_SIGNING_KEY_FILE":  "/etc/tolo/signing-key.pem",
					"INTERNAL_JWT_SIGNING_KEY_ID":    "dev-key-1",
					"TOLO_GATEWAY_DESTINATIONS_FILE": "/etc/tolo/gateway/destinations.json",
					"IDP_ISSUER":                     tt.issuer,
					"IDP_AUDIENCE":                   idpAudienceFor(tt.issuer),
					"IDP_LEGACY_EVENTS_WRITE_SCOPE":  tt.raw,
				}[key]
			})

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
