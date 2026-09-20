package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
)

func newFallbackHandler(t *testing.T) http.Handler {
	t.Helper()

	return httpapi.NewHandler(
		httpapi.HealthRoutes(httpapi.NewReadiness()),
		httpapi.PublicRoutes(httpapi.NewJWKSHandler(newTestIssuer(t))),
		httpapi.WorkloadRoutes(),
		httpapi.FallbackRoutes(),
	)
}

func newConnectRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	return req
}

func TestFallbackAnswersConnectRequestsWithUnimplemented(t *testing.T) {
	t.Parallel()

	for _, procedure := range []string{"/greet.v1.GreetService/Greet", "/greet.v1.GreetService/Absent"} {
		res := sendRequest(t, newFallbackHandler(t), newConnectRequest(procedure))

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

func TestFallbackAnswersOtherRequestsWithNotFound(t *testing.T) {
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

	handler := newFallbackHandler(t)

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

func TestFallbackAnswersGetRequestsWithNotFound(t *testing.T) {
	t.Parallel()

	res := sendRequest(t, newFallbackHandler(t), httptest.NewRequest(http.MethodGet, "/absent", nil))

	if got, want := res.status, http.StatusNotFound; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
}

func TestFallbackLeavesTheRegisteredRoutesAlone(t *testing.T) {
	t.Parallel()

	handler := newFallbackHandler(t)

	for _, path := range []string{"/healthz", "/readyz", httpapi.JWKSPath} {
		res := sendRequest(t, handler, httptest.NewRequest(http.MethodGet, path, nil))

		if got, want := res.status, http.StatusOK; got != want {
			t.Errorf("GET %s status = %d, want %d", path, got, want)
		}
	}
}
