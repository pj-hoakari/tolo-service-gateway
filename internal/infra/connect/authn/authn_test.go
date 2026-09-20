package authn_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	unknownProcedure       = "/greet.v1.GreetService/Absent"
)

type counter struct {
	calls int
}

func (c *counter) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	c.calls++

	w.WriteHeader(http.StatusTeapot)
}

func newRegistry(t *testing.T) *registry.Registry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	return built
}

func connectRequest(procedure string, headers map[string][]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	for name, values := range headers {
		req.Header[http.CanonicalHeaderKey(name)] = values
	}

	return req
}

func TestMiddlewarePassesAnonymousProceduresWithoutCredentials(t *testing.T) {
	t.Parallel()

	next, fallback := &counter{calls: 0}, &counter{calls: 0}
	res := httptest.NewRecorder()

	authn.Middleware(newRegistry(t), next, fallback).ServeHTTP(res, connectRequest(anonymousProcedure, nil))

	if next.calls != 1 {
		t.Errorf("next calls = %d, want 1", next.calls)
	}

	if fallback.calls != 0 {
		t.Errorf("fallback calls = %d, want 0", fallback.calls)
	}
}

func TestMiddlewareDefersToTheFallback(t *testing.T) {
	t.Parallel()

	tests := map[string]*http.Request{
		"a request no RPC protocol uses": httptest.NewRequest(http.MethodGet, anonymousProcedure, nil),
		"a method no RPC protocol uses":  connectRequest(anonymousProcedure, nil),
		"an unregistered procedure":      connectRequest(unknownProcedure, nil),
	}

	tests["a method no RPC protocol uses"].Method = http.MethodPut

	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			next, fallback := &counter{calls: 0}, &counter{calls: 0}
			res := httptest.NewRecorder()

			authn.Middleware(newRegistry(t), next, fallback).ServeHTTP(res, req)

			if next.calls != 0 {
				t.Errorf("next calls = %d, want 0", next.calls)
			}

			if fallback.calls != 1 {
				t.Errorf("fallback calls = %d, want 1", fallback.calls)
			}
		})
	}
}

func TestMiddlewareRejectsWithoutReachingTheForwarder(t *testing.T) {
	t.Parallel()

	tests := map[string]*http.Request{
		"an anonymous procedure carrying a workload credential": connectRequest(anonymousProcedure, map[string][]string{
			"Workload-Authorization": {""},
		}),
		"an anonymous procedure carrying a serverless credential": connectRequest(anonymousProcedure, map[string][]string{
			"X-Serverless-Authorization": {"Bearer outside"},
		}),
		"an anonymous procedure carrying an external token": connectRequest(anonymousProcedure, map[string][]string{
			"Authorization": {"Bearer outside"},
		}),
		"an anonymous procedure carrying a DPoP proof": connectRequest(anonymousProcedure, map[string][]string{
			"DPoP": {"proof"},
		}),
		"an authenticated procedure without credentials": connectRequest(authenticatedProcedure, nil),
		"a service-only procedure without credentials":   connectRequest(serviceOnlyProcedure, nil),
	}

	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			next, fallback := &counter{calls: 0}, &counter{calls: 0}
			res := httptest.NewRecorder()

			authn.Middleware(newRegistry(t), next, fallback).ServeHTTP(res, req)

			if next.calls != 0 {
				t.Errorf("next calls = %d, want 0", next.calls)
			}

			if fallback.calls != 0 {
				t.Errorf("fallback calls = %d, want 0", fallback.calls)
			}

			if got, want := res.Code, http.StatusUnauthorized; got != want {
				t.Errorf("status = %d, want %d", got, want)
			}

			var body struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}

			if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Fatalf("Unmarshal(%q) error = %v", res.Body.String(), err)
			}

			if got, want := body.Code, "unauthenticated"; got != want {
				t.Errorf("code = %q, want %q", got, want)
			}

			if got, want := body.Message, "unauthenticated"; got != want {
				t.Errorf("message = %q, want %q", got, want)
			}
		})
	}
}
