package main

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env             map[string]string
		wantErr         bool
		wantErrContains []string
		wantListenAddr  string
		wantJWKSURL     string
		wantIssuerID    string
		wantAudience    string
	}{
		"all values set": {
			env: map[string]string{
				"SERVER_ADDR":           "127.0.0.1:9000",
				"INTERNAL_JWKS_URL":     "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_ISSUER":   "service-gateway",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantListenAddr:  "127.0.0.1:9000",
			wantJWKSURL:     "http://server:8080/.well-known/jwks.json",
			wantIssuerID:    "service-gateway",
			wantAudience:    "tolo-testbackend",
		},
		"only the required values set": {
			env: map[string]string{
				"INTERNAL_JWKS_URL":     "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_ISSUER":   "service-gateway",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantListenAddr:  ":8080",
			wantJWKSURL:     "http://server:8080/.well-known/jwks.json",
			wantIssuerID:    "service-gateway",
			wantAudience:    "tolo-testbackend",
		},
		"empty listen address falls back to the default": {
			env: map[string]string{
				"SERVER_ADDR":           "",
				"INTERNAL_JWKS_URL":     "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_ISSUER":   "service-gateway",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantListenAddr:  ":8080",
			wantJWKSURL:     "http://server:8080/.well-known/jwks.json",
			wantIssuerID:    "service-gateway",
			wantAudience:    "tolo-testbackend",
		},
		"values are not trimmed": {
			env: map[string]string{
				"SERVER_ADDR":           " :8081 ",
				"INTERNAL_JWKS_URL":     " http://server:8080/.well-known/jwks.json ",
				"INTERNAL_JWT_ISSUER":   " service-gateway ",
				"INTERNAL_JWT_AUDIENCE": " tolo-testbackend ",
			},
			wantErr:         false,
			wantErrContains: nil,
			wantListenAddr:  " :8081 ",
			wantJWKSURL:     " http://server:8080/.well-known/jwks.json ",
			wantIssuerID:    " service-gateway ",
			wantAudience:    " tolo-testbackend ",
		},
		"missing jwks url": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":   "service-gateway",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         true,
			wantErrContains: []string{"INTERNAL_JWKS_URL"},
			wantListenAddr:  "",
			wantJWKSURL:     "",
			wantIssuerID:    "",
			wantAudience:    "",
		},
		"empty jwks url is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWKS_URL":     "",
				"INTERNAL_JWT_ISSUER":   "service-gateway",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         true,
			wantErrContains: []string{"INTERNAL_JWKS_URL"},
			wantListenAddr:  "",
			wantJWKSURL:     "",
			wantIssuerID:    "",
			wantAudience:    "",
		},
		"missing issuer": {
			env: map[string]string{
				"INTERNAL_JWKS_URL":     "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         true,
			wantErrContains: []string{"INTERNAL_JWT_ISSUER"},
			wantListenAddr:  "",
			wantJWKSURL:     "",
			wantIssuerID:    "",
			wantAudience:    "",
		},
		"empty issuer is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWKS_URL":     "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_ISSUER":   "",
				"INTERNAL_JWT_AUDIENCE": "tolo-testbackend",
			},
			wantErr:         true,
			wantErrContains: []string{"INTERNAL_JWT_ISSUER"},
			wantListenAddr:  "",
			wantJWKSURL:     "",
			wantIssuerID:    "",
			wantAudience:    "",
		},
		"missing audience": {
			env: map[string]string{
				"INTERNAL_JWKS_URL":   "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_ISSUER": "service-gateway",
			},
			wantErr:         true,
			wantErrContains: []string{"INTERNAL_JWT_AUDIENCE"},
			wantListenAddr:  "",
			wantJWKSURL:     "",
			wantIssuerID:    "",
			wantAudience:    "",
		},
		"empty audience is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWKS_URL":     "http://server:8080/.well-known/jwks.json",
				"INTERNAL_JWT_ISSUER":   "service-gateway",
				"INTERNAL_JWT_AUDIENCE": "",
			},
			wantErr:         true,
			wantErrContains: []string{"INTERNAL_JWT_AUDIENCE"},
			wantListenAddr:  "",
			wantJWKSURL:     "",
			wantIssuerID:    "",
			wantAudience:    "",
		},
		"every required value missing": {
			env:     map[string]string{},
			wantErr: true,
			wantErrContains: []string{
				"INTERNAL_JWKS_URL",
				"INTERNAL_JWT_ISSUER",
				"INTERNAL_JWT_AUDIENCE",
			},
			wantListenAddr: "",
			wantJWKSURL:    "",
			wantIssuerID:   "",
			wantAudience:   "",
		},
		"a listen address alone does not satisfy the required values": {
			env: map[string]string{
				"SERVER_ADDR": ":9000",
			},
			wantErr: true,
			wantErrContains: []string{
				"INTERNAL_JWKS_URL",
				"INTERNAL_JWT_ISSUER",
				"INTERNAL_JWT_AUDIENCE",
			},
			wantListenAddr: "",
			wantJWKSURL:    "",
			wantIssuerID:   "",
			wantAudience:   "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := loadConfig(func(key string) string {
				return tt.env[key]
			})

			if tt.wantErr {
				if err == nil {
					t.Fatalf("loadConfig() error = nil, want error")
				}

				for _, want := range tt.wantErrContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("loadConfig() error = %q, want it to mention %q", err.Error(), want)
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("loadConfig() error = %v, want nil", err)
			}

			if got := cfg.ListenAddr; got != tt.wantListenAddr {
				t.Errorf("ListenAddr = %q, want %q", got, tt.wantListenAddr)
			}

			if got := cfg.JWKSURL; got != tt.wantJWKSURL {
				t.Errorf("JWKSURL = %q, want %q", got, tt.wantJWKSURL)
			}

			if got := cfg.IssuerID; got != tt.wantIssuerID {
				t.Errorf("IssuerID = %q, want %q", got, tt.wantIssuerID)
			}

			if got := cfg.Audience; got != tt.wantAudience {
				t.Errorf("Audience = %q, want %q", got, tt.wantAudience)
			}
		})
	}
}
