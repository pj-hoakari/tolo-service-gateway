package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
)

func TestNewHandlerMountsEveryFace(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewHandler(
		httpapi.HealthRoutes(httpapi.NewReadiness()),
		httpapi.PublicRoutes(httpapi.NewJWKSHandler(newTestIssuer(t))),
		httpapi.WorkloadRoutes(),
	)

	for _, path := range []string{"/healthz", "/readyz", httpapi.JWKSPath} {
		res := sendRequest(t, handler, httptest.NewRequest(http.MethodGet, path, nil))

		if got, want := res.status, http.StatusOK; got != want {
			t.Errorf("GET %s status = %d, want %d", path, got, want)
		}
	}

	unknown := sendRequest(t, handler, httptest.NewRequest(http.MethodPost, "/greet.v1.GreetService/Greet", nil))

	if got, want := unknown.status, http.StatusNotFound; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}
}

func TestNewHandlerWithoutPublicRoutesHidesJWKS(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewHandler(httpapi.HealthRoutes(httpapi.NewReadiness()))

	res := sendRequest(t, handler, httptest.NewRequest(http.MethodGet, httpapi.JWKSPath, nil))

	if got, want := res.status, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	t.Parallel()

	handler := httpapi.NewHandler(httpapi.HealthRoutes(httpapi.NewReadiness()))

	res := sendRequest(t, handler, httptest.NewRequest(http.MethodPost, "/greet.v1.GreetService/Greet", nil))

	if got, want := res.status, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}
