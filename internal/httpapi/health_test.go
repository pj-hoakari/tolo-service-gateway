package httpapi_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
)

func TestHealthz(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	handler := httpapi.NewHandler(httpapi.HealthRoutes(httpapi.NewReadiness()))
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

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

func TestReadyzWithoutChecks(t *testing.T) {
	t.Parallel()

	status, body := requestReadyz(t, httpapi.NewHandler(httpapi.HealthRoutes(httpapi.NewReadiness())))

	if want := http.StatusOK; status != want {
		t.Fatalf("status = %d, want %d", status, want)
	}

	if want := "ok"; body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestReadyzWithPassingChecks(t *testing.T) {
	t.Parallel()

	readiness := httpapi.NewReadiness()
	readiness.Register("signing-key", func(context.Context) error { return nil })
	readiness.Register("trust-store", func(context.Context) error { return nil })

	status, body := requestReadyz(t, httpapi.NewHandler(httpapi.HealthRoutes(readiness)))

	if want := http.StatusOK; status != want {
		t.Fatalf("status = %d, want %d", status, want)
	}

	if want := "ok"; body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestReadyzWithFailingCheck(t *testing.T) {
	t.Parallel()

	readiness := httpapi.NewReadiness()
	readiness.Register("signing-key", func(context.Context) error { return nil })
	readiness.Register("trust-store", func(context.Context) error {
		return errors.New("trust store is empty")
	})

	status, body := requestReadyz(t, httpapi.NewHandler(httpapi.HealthRoutes(readiness)))

	if want := http.StatusServiceUnavailable; status != want {
		t.Fatalf("status = %d, want %d", status, want)
	}

	if want := "not ready"; body != want {
		t.Errorf("body = %q, want %q", body, want)
	}

	for _, leak := range []string{"trust store is empty", "trust-store"} {
		if strings.Contains(body, leak) {
			t.Errorf("body = %q, want it to not disclose %q", body, leak)
		}
	}
}

func TestHealthzStaysOKWhileNotReady(t *testing.T) {
	t.Parallel()

	readiness := httpapi.NewReadiness()
	readiness.Register("signing-key", func(context.Context) error {
		return errors.New("signing key is missing")
	})

	handler := httpapi.NewHandler(httpapi.HealthRoutes(readiness))

	if status, _ := requestReadyz(t, handler); status != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want %d", status, http.StatusServiceUnavailable)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	res := rec.Result()
	defer res.Body.Close()

	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Fatalf("healthz status = %d, want %d", got, want)
	}
}

func TestReadyzSeesChecksRegisteredAfterNewHandler(t *testing.T) {
	t.Parallel()

	readiness := httpapi.NewReadiness()
	handler := httpapi.NewHandler(httpapi.HealthRoutes(readiness))

	if status, _ := requestReadyz(t, handler); status != http.StatusOK {
		t.Fatalf("readyz status = %d, want %d", status, http.StatusOK)
	}

	readiness.Register("signing-key", func(context.Context) error {
		return errors.New("signing key is missing")
	})

	if status, _ := requestReadyz(t, handler); status != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want %d", status, http.StatusServiceUnavailable)
	}
}

func TestReadinessCheckReceivesRequestContext(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}

	readiness := httpapi.NewReadiness()
	readiness.Register("context", func(ctx context.Context) error {
		if ctx.Value(ctxKey{}) != "value" {
			return errors.New("request context was not passed to the check")
		}

		return nil
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, "value"))

	httpapi.NewHandler(httpapi.HealthRoutes(readiness)).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func requestReadyz(t *testing.T, handler http.Handler) (int, string) {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	res := rec.Result()
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return res.StatusCode, string(body)
}
