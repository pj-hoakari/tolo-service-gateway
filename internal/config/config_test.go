package config_test

import (
	"strings"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/config"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env                map[string]string
		wantErr            bool
		wantErrContains    []string
		wantListenAddr     string
		wantIssuerID       string
		wantSigningKeyFile string
	}{
		"all values set": {
			env: map[string]string{
				"SERVER_ADDR":                   "127.0.0.1:9000",
				"INTERNAL_JWT_ISSUER":           "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE": "/etc/tolo/signing-key.pem",
			},
			wantErr:            false,
			wantErrContains:    nil,
			wantListenAddr:     "127.0.0.1:9000",
			wantIssuerID:       "service-gateway",
			wantSigningKeyFile: "/etc/tolo/signing-key.pem",
		},
		"listen address falls back to the default": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":           "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE": "/etc/tolo/signing-key.pem",
			},
			wantErr:            false,
			wantErrContains:    nil,
			wantListenAddr:     ":8080",
			wantIssuerID:       "service-gateway",
			wantSigningKeyFile: "/etc/tolo/signing-key.pem",
		},
		"empty listen address falls back to the default": {
			env: map[string]string{
				"SERVER_ADDR":                   "",
				"INTERNAL_JWT_ISSUER":           "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE": "/etc/tolo/signing-key.pem",
			},
			wantErr:            false,
			wantErrContains:    nil,
			wantListenAddr:     ":8080",
			wantIssuerID:       "service-gateway",
			wantSigningKeyFile: "/etc/tolo/signing-key.pem",
		},
		"values are not trimmed": {
			env: map[string]string{
				"SERVER_ADDR":                   " :8081 ",
				"INTERNAL_JWT_ISSUER":           " service-gateway ",
				"INTERNAL_JWT_SIGNING_KEY_FILE": " /etc/tolo/signing-key.pem ",
			},
			wantErr:            false,
			wantErrContains:    nil,
			wantListenAddr:     " :8081 ",
			wantIssuerID:       " service-gateway ",
			wantSigningKeyFile: " /etc/tolo/signing-key.pem ",
		},
		"missing issuer": {
			env: map[string]string{
				"INTERNAL_JWT_SIGNING_KEY_FILE": "/etc/tolo/signing-key.pem",
			},
			wantErr:            true,
			wantErrContains:    []string{"INTERNAL_JWT_ISSUER"},
			wantListenAddr:     "",
			wantIssuerID:       "",
			wantSigningKeyFile: "",
		},
		"empty issuer is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":           "",
				"INTERNAL_JWT_SIGNING_KEY_FILE": "/etc/tolo/signing-key.pem",
			},
			wantErr:            true,
			wantErrContains:    []string{"INTERNAL_JWT_ISSUER"},
			wantListenAddr:     "",
			wantIssuerID:       "",
			wantSigningKeyFile: "",
		},
		"missing signing key file": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER": "service-gateway",
			},
			wantErr:            true,
			wantErrContains:    []string{"INTERNAL_JWT_SIGNING_KEY_FILE"},
			wantListenAddr:     "",
			wantIssuerID:       "",
			wantSigningKeyFile: "",
		},
		"empty signing key file is treated as unset": {
			env: map[string]string{
				"INTERNAL_JWT_ISSUER":           "service-gateway",
				"INTERNAL_JWT_SIGNING_KEY_FILE": "",
			},
			wantErr:            true,
			wantErrContains:    []string{"INTERNAL_JWT_SIGNING_KEY_FILE"},
			wantListenAddr:     "",
			wantIssuerID:       "",
			wantSigningKeyFile: "",
		},
		"both required values missing": {
			env:                map[string]string{},
			wantErr:            true,
			wantErrContains:    []string{"INTERNAL_JWT_ISSUER", "INTERNAL_JWT_SIGNING_KEY_FILE"},
			wantListenAddr:     "",
			wantIssuerID:       "",
			wantSigningKeyFile: "",
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

			if got := cfg.SigningKeyFile; got != tt.wantSigningKeyFile {
				t.Errorf("SigningKeyFile = %q, want %q", got, tt.wantSigningKeyFile)
			}
		})
	}
}
