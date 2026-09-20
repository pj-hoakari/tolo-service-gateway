package config_test

import (
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
