package registry_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pj-hoakari/protoc-gen-authz-go/authz"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

func writeDestinationsFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "destinations.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write the destinations file: %v", err)
	}

	return path
}

func TestLoadDestinations(t *testing.T) {
	t.Parallel()

	path := writeDestinationsFile(t, `{
  "destinations": {
    "tolo-testbackend": { "url": "http://testbackend:8080" },
    "tolo-tenant-management": { "url": "https://tenant-management.example.com/" }
  }
}
`)

	destinations, err := registry.LoadDestinations(path)
	if err != nil {
		t.Fatalf("LoadDestinations() error = %v, want nil", err)
	}

	if got, want := len(destinations), 2; got != want {
		t.Fatalf("len(destinations) = %d, want %d", got, want)
	}

	backend, ok := destinations["tolo-testbackend"]
	if !ok {
		t.Fatalf("destinations[%q] is missing", "tolo-testbackend")
	}

	if got, want := backend.URL.String(), "http://testbackend:8080"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}

	if got, want := backend.URL.Host, "testbackend:8080"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
}

func TestLoadDestinationsRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		content         string
		wantErrContains []string
	}{
		"an unknown top-level field": {
			content:         `{"destinations": {"a": {"url": "http://a:8080"}}, "extra": 1}`,
			wantErrContains: []string{"extra"},
		},
		"an unknown destination field": {
			content:         `{"destinations": {"a": {"url": "http://a:8080", "identity": "spiffe://a"}}}`,
			wantErrContains: []string{"identity"},
		},
		"data after the top-level object": {
			content:         `{"destinations": {"a": {"url": "http://a:8080"}}} {"destinations": {}}`,
			wantErrContains: []string{"after the top-level object"},
		},
		"broken JSON": {
			content:         `{"destinations":`,
			wantErrContains: []string{"destinations.json"},
		},
		"no destinations member": {
			content:         `{}`,
			wantErrContains: []string{"no destination"},
		},
		"an empty destinations member": {
			content:         `{"destinations": {}}`,
			wantErrContains: []string{"no destination"},
		},
		"an empty service ID": {
			content:         `{"destinations": {"": {"url": "http://a:8080"}}}`,
			wantErrContains: []string{"empty service ID"},
		},
		"an empty URL": {
			content:         `{"destinations": {"a": {"url": ""}}}`,
			wantErrContains: []string{"URL is empty"},
		},
		"a missing URL": {
			content:         `{"destinations": {"a": {}}}`,
			wantErrContains: []string{"URL is empty"},
		},
		"another scheme": {
			content:         `{"destinations": {"a": {"url": "grpc://a:8080"}}}`,
			wantErrContains: []string{"scheme"},
		},
		"no scheme": {
			content:         `{"destinations": {"a": {"url": "a:8080"}}}`,
			wantErrContains: []string{"scheme"},
		},
		"no host": {
			content:         `{"destinations": {"a": {"url": "http:///"}}}`,
			wantErrContains: []string{"no host"},
		},
		"user information": {
			content:         `{"destinations": {"a": {"url": "http://user@a:8080"}}}`,
			wantErrContains: []string{"user information"},
		},
		"a query": {
			content:         `{"destinations": {"a": {"url": "http://a:8080?x=1"}}}`,
			wantErrContains: []string{"query"},
		},
		"an empty forced query": {
			content:         `{"destinations": {"a": {"url": "http://a:8080?"}}}`,
			wantErrContains: []string{"query"},
		},
		"a fragment": {
			content:         `{"destinations": {"a": {"url": "http://a:8080#x"}}}`,
			wantErrContains: []string{"fragment"},
		},
		"a path": {
			content:         `{"destinations": {"a": {"url": "http://a:8080/api"}}}`,
			wantErrContains: []string{"path"},
		},
		"every destination is reported": {
			content:         `{"destinations": {"a": {"url": "grpc://a"}, "b": {"url": "http://b/api"}}}`,
			wantErrContains: []string{`destination "a"`, `destination "b"`},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			destinations, err := registry.LoadDestinations(writeDestinationsFile(t, tt.content))
			if err == nil {
				t.Fatalf("LoadDestinations() error = nil, want error")
			}

			if destinations != nil {
				t.Errorf("LoadDestinations() destinations = %v, want nil", destinations)
			}

			if !errors.Is(err, registry.ErrInvalidDestinations) {
				t.Errorf("LoadDestinations() error = %v, want it to match %v", err, registry.ErrInvalidDestinations)
			}

			for _, want := range tt.wantErrContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("LoadDestinations() error = %q, want it to mention %q", err.Error(), want)
				}
			}
		})
	}
}

func TestLoadDestinationsRejectsAnUnreadableFile(t *testing.T) {
	t.Parallel()

	_, err := registry.LoadDestinations(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatalf("LoadDestinations() error = nil, want error")
	}

	if !errors.Is(err, registry.ErrDestinationsFile) {
		t.Errorf("LoadDestinations() error = %v, want it to match %v", err, registry.ErrDestinationsFile)
	}
}

func TestCheckDestinations(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		content         string
		wantErrs        []error
		wantErrContains []string
	}{
		"every destination is configured and used": {
			content:  `{"destinations": {"tolo-testbackend": {"url": "http://testbackend:8080"}}}`,
			wantErrs: nil,
		},
		"a referenced destination is not configured": {
			content:         `{"destinations": {"tolo-other": {"url": "http://other:8080"}}}`,
			wantErrs:        []error{registry.ErrMissingDestination, registry.ErrUnusedDestination},
			wantErrContains: []string{"tolo-testbackend", "tolo-other"},
		},
		"a configured destination is not referenced": {
			content: `{"destinations": {
				"tolo-testbackend": {"url": "http://testbackend:8080"},
				"tolo-other": {"url": "http://other:8080"}
			}}`,
			wantErrs:        []error{registry.ErrUnusedDestination},
			wantErrContains: []string{"tolo-other"},
		},
	}

	built, err := registry.Build(
		[]registry.Binding{{
			Service:     testService,
			Destination: testDestination,
			Policies:    authz.Policies{testProcedure: {Level: authz.LevelPublic}},
		}},
		registry.Overrides{},
		singleMethodResolver(t),
	)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			destinations, err := registry.LoadDestinations(writeDestinationsFile(t, tt.content))
			if err != nil {
				t.Fatalf("LoadDestinations() error = %v, want nil", err)
			}

			err = built.CheckDestinations(destinations)

			if len(tt.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("CheckDestinations() error = %v, want nil", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("CheckDestinations() error = nil, want error")
			}

			for _, want := range tt.wantErrs {
				if !errors.Is(err, want) {
					t.Errorf("CheckDestinations() error = %v, want it to match %v", err, want)
				}
			}

			for _, want := range tt.wantErrContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("CheckDestinations() error = %q, want it to mention %q", err.Error(), want)
				}
			}
		})
	}
}
