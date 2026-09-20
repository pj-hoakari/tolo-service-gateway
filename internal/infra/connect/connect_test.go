package connect_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	infraconnect "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	greetMountPath     = "/greet.v1.GreetService/"
	anonymousProcedure = "/greet.v1.GreetService/Ping"
	absentProcedure    = "/greet.v1.GreetService/Absent"
)

type response struct {
	status int
	body   string
}

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

func newRPCHandler(t *testing.T, handlers map[string]http.Handler) http.Handler {
	t.Helper()

	return httpapi.NewHandler(infraconnect.Routes(newRegistry(t), handlers))
}

func newConnectRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	return req
}

func sendRequest(t *testing.T, handler http.Handler, req *http.Request) response {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return response{status: res.StatusCode, body: string(body)}
}

func TestRoutesAnswerConnectRequestsWithUnimplemented(t *testing.T) {
	t.Parallel()

	handler := newRPCHandler(t, nil)

	for _, procedure := range []string{"/greet.v1.GreetService/Greet", absentProcedure} {
		res := sendRequest(t, handler, newConnectRequest(procedure))

		if got, want := res.status, http.StatusNotImplemented; got != want {
			t.Errorf("POST %s status = %d, want %d", procedure, got, want)
		}

		var body struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}

		if err := json.Unmarshal([]byte(res.body), &body); err != nil {
			t.Fatalf("Unmarshal(%q) error = %v", res.body, err)
		}

		if got, want := body.Code, "unimplemented"; got != want {
			t.Errorf("code = %q, want %q", got, want)
		}

		if strings.Contains(body.Message, procedure) {
			t.Errorf("message = %q, want it not to name the procedure", body.Message)
		}
	}
}

func TestRoutesAnswerOtherRequestsWithNotFound(t *testing.T) {
	t.Parallel()

	tests := map[string]*http.Request{
		"a request with a body no RPC protocol uses": httptest.NewRequest(http.MethodPost, "/absent", strings.NewReader("hello")),
		"a request with a method no RPC protocol uses": httptest.NewRequest(
			http.MethodPut,
			"/greet.v1.GreetService/Greet",
			strings.NewReader("{}"),
		),
	}

	tests["a request with a body no RPC protocol uses"].Header.Set("Content-Type", "text/plain")
	tests["a request with a method no RPC protocol uses"].Header.Set("Content-Type", "application/json")

	handler := newRPCHandler(t, nil)

	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			res := sendRequest(t, handler, req)

			if got, want := res.status, http.StatusNotFound; got != want {
				t.Errorf("status = %d, want %d", got, want)
			}
		})
	}
}

func TestRoutesAnswerGetRequestsWithNotFound(t *testing.T) {
	t.Parallel()

	res := sendRequest(t, newRPCHandler(t, nil), httptest.NewRequest(http.MethodGet, "/absent", nil))

	if got, want := res.status, http.StatusNotFound; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
}

func TestRoutesLeaveTheOtherFacesAlone(t *testing.T) {
	t.Parallel()

	jwks := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := httpapi.NewHandler(
		httpapi.HealthRoutes(httpapi.NewReadiness()),
		httpapi.PublicRoutes(jwks),
		infraconnect.Routes(newRegistry(t), nil),
	)

	for _, path := range []string{"/healthz", "/readyz", httpapi.JWKSPath} {
		res := sendRequest(t, handler, httptest.NewRequest(http.MethodGet, path, nil))

		if got, want := res.status, http.StatusOK; got != want {
			t.Errorf("GET %s status = %d, want %d", path, got, want)
		}
	}
}

func TestRoutesSendRegisteredProceduresThroughAuthentication(t *testing.T) {
	t.Parallel()

	mounted := &counter{calls: 0}
	handler := newRPCHandler(t, map[string]http.Handler{greetMountPath: mounted})

	res := sendRequest(t, handler, newConnectRequest(anonymousProcedure))

	if got, want := res.status, http.StatusTeapot; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}

	if mounted.calls != 1 {
		t.Errorf("mounted handler calls = %d, want 1", mounted.calls)
	}
}

func TestRoutesRejectCredentialsOnRegisteredProcedures(t *testing.T) {
	t.Parallel()

	mounted := &counter{calls: 0}
	handler := newRPCHandler(t, map[string]http.Handler{greetMountPath: mounted})

	req := newConnectRequest(anonymousProcedure)
	req.Header.Set("Authorization", "Bearer outside")

	res := sendRequest(t, handler, req)

	if got, want := res.status, http.StatusUnauthorized; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}

	if mounted.calls != 0 {
		t.Errorf("mounted handler calls = %d, want 0", mounted.calls)
	}
}

func TestRoutesAnswerUnregisteredProceduresUnderAMountedPath(t *testing.T) {
	t.Parallel()

	mounted := &counter{calls: 0}
	handler := newRPCHandler(t, map[string]http.Handler{greetMountPath: mounted})

	res := sendRequest(t, handler, newConnectRequest(absentProcedure))

	if got, want := res.status, http.StatusNotImplemented; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}

	if mounted.calls != 0 {
		t.Errorf("mounted handler calls = %d, want 0", mounted.calls)
	}
}
