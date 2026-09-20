package authn_test

import (
	"net/http"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	anonymousProcedure     = "/greet.v1.GreetService/Ping"
	authenticatedProcedure = "/greet.v1.GreetService/Greet"
	serviceOnlyProcedure   = "/tolo.tenant.v1.TenantService/GetEvent"
)

func lookup(t *testing.T, procedure string) registry.Entry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	entry, registered := built.Lookup(procedure)
	if !registered {
		t.Fatalf("Lookup(%q) is not registered", procedure)
	}

	return entry
}

func headerWith(values map[string][]string) http.Header {
	header := make(http.Header)

	for name, value := range values {
		header[http.CanonicalHeaderKey(name)] = value
	}

	return header
}

func TestRejectAcceptsAnAnonymousProcedureWithoutCredentials(t *testing.T) {
	t.Parallel()

	reason, rejected := authn.Reject(headerWith(nil), lookup(t, anonymousProcedure))

	if rejected {
		t.Errorf("Reject() = %q, true, want it accepted", reason)
	}

	if reason != "" {
		t.Errorf("reason = %q, want it empty", reason)
	}
}

func TestRejectNamesTheReason(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		procedure string
		header    map[string][]string
		want      string
	}{
		"an anonymous procedure carrying a workload credential": {
			procedure: anonymousProcedure,
			header:    map[string][]string{"Workload-Authorization": {""}},
			want:      authn.ReasonWorkloadAuthorization,
		},
		"an anonymous procedure carrying a serverless credential": {
			procedure: anonymousProcedure,
			header:    map[string][]string{"X-Serverless-Authorization": {"Bearer outside"}},
			want:      authn.ReasonWorkloadAuthorization,
		},
		"an anonymous procedure carrying an external token": {
			procedure: anonymousProcedure,
			header:    map[string][]string{"Authorization": {"Bearer outside"}},
			want:      authn.ReasonExternalAuthorization,
		},
		"an anonymous procedure carrying a DPoP proof": {
			procedure: anonymousProcedure,
			header:    map[string][]string{"DPoP": {"proof"}},
			want:      authn.ReasonExternalAuthorization,
		},
		"a workload credential is named before an external token": {
			procedure: anonymousProcedure,
			header: map[string][]string{
				"Workload-Authorization": {"Bearer inside"},
				"Authorization":          {"Bearer outside"},
			},
			want: authn.ReasonWorkloadAuthorization,
		},
		"an authenticated procedure without credentials": {
			procedure: authenticatedProcedure,
			header:    nil,
			want:      authn.ReasonAnonymousRejected,
		},
		"a service-only procedure without credentials": {
			procedure: serviceOnlyProcedure,
			header:    nil,
			want:      authn.ReasonAnonymousRejected,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reason, rejected := authn.Reject(headerWith(test.header), lookup(t, test.procedure))

			if !rejected {
				t.Fatal("Reject() accepted the request, want it rejected")
			}

			if reason != test.want {
				t.Errorf("reason = %q, want %q", reason, test.want)
			}
		})
	}
}
