package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
)

func TestHealthz(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	httpapi.NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	res := rec.Result()
	defer res.Body.Close()

	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if got, want := string(body), "ok"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	httpapi.NewHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/greet.v1.GreetService/Greet", nil))

	res := rec.Result()
	defer res.Body.Close()

	if got, want := res.StatusCode, http.StatusNotFound; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}
