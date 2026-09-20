package connect_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connectrpc "connectrpc.com/connect"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"google.golang.org/protobuf/reflect/protoregistry"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	infraconnect "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	greetMountPath         = "/greet.v1.GreetService/"
	anonymousProcedure     = "/greet.v1.GreetService/Ping"
	authenticatedProcedure = "/greet.v1.GreetService/Greet"
	absentProcedure        = "/greet.v1.GreetService/Absent"
)

const clientTraceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

const clientTraceID = "0123456789abcdef0123456789abcdef"

type response struct {
	status int
	body   string
	header http.Header
}

type counter struct {
	calls int
}

func (c *counter) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	c.calls++

	w.WriteHeader(http.StatusTeapot)
}

type localGreetService struct {
	greetv1connect.UnimplementedGreetServiceHandler
}

func (localGreetService) Ping(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
	return connectrpc.NewResponse(&greetv1.PingResponse{Message: "pong"}), nil
}

type fixture struct {
	handler http.Handler
	audit   *bytes.Buffer
	spans   *tracetest.SpanRecorder
}

func newRegistry(t *testing.T) *registry.Registry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	return built
}

func newFixture(t *testing.T, handlers map[string]http.Handler, trustedProxyHops int) fixture {
	t.Helper()

	logs := &bytes.Buffer{}
	spans := tracetest.NewSpanRecorder()

	routes := infraconnect.Routes(infraconnect.Config{
		Registry: newRegistry(t),
		Handlers: handlers,
		Audit: audit.NewEmitter(logging.NewLogger(logs, logging.Options{
			Level:     slog.LevelInfo,
			AddSource: false,
			ProjectID: "",
		})),
		TracerProvider:   sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)),
		TrustedProxyHops: trustedProxyHops,
	})

	return fixture{handler: httpapi.NewHandler(routes), audit: logs, spans: spans}
}

func newRPCHandler(t *testing.T, handlers map[string]http.Handler) http.Handler {
	t.Helper()

	return newFixture(t, handlers, 0).handler
}

func newGreetHandlers(t *testing.T) map[string]http.Handler {
	t.Helper()

	path, handler := greetv1connect.NewGreetServiceHandler(
		localGreetService{UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{}},
		connectrpc.WithInterceptors(infraconnect.AuditInterceptor()),
	)

	return map[string]http.Handler{path: handler}
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

	return response{status: res.StatusCode, body: string(body), header: res.Header}
}

func auditRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()

	text := strings.TrimSpace(logs.String())
	if text == "" {
		return nil
	}

	var records []map[string]any

	for _, line := range strings.Split(text, "\n") {
		var entry map[string]any

		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}

		if entry["message"] != "audit" {
			continue
		}

		record, ok := entry["audit"].(map[string]any)
		if !ok {
			t.Fatalf("audit = %#v, want a group", entry["audit"])
		}

		records = append(records, record)
	}

	return records
}

func singleAuditRecord(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()

	records := auditRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want 1 (log = %q)", len(records), logs.String())
	}

	return records[0]
}

func assertAudit(t *testing.T, record map[string]any, want map[string]any) {
	t.Helper()

	for key, value := range want {
		if got := record[key]; got != value {
			t.Errorf("audit.%s = %#v, want %#v", key, got, value)
		}
	}
}

func assertCorrelated(t *testing.T, record map[string]any) {
	t.Helper()

	traceID, ok := record["trace_id"].(string)
	if !ok || len(traceID) != 32 || traceID == strings.Repeat("0", 32) {
		t.Errorf("audit.trace_id = %#v, want a valid trace ID", record["trace_id"])
	}

	spanID, ok := record["span_id"].(string)
	if !ok || len(spanID) != 16 || spanID == strings.Repeat("0", 16) {
		t.Errorf("audit.span_id = %#v, want a valid span ID", record["span_id"])
	}
}

func assertNoCorrelationHeaders(t *testing.T, header http.Header) {
	t.Helper()

	for _, name := range []string{"X-Request-Id", "Traceparent", "Tracestate"} {
		if value, ok := header[http.CanonicalHeaderKey(name)]; ok {
			t.Errorf("response header %s = %v, want no correlation header", name, value)
		}
	}
}

func TestRoutesAnswerConnectRequestsWithUnimplemented(t *testing.T) {
	t.Parallel()

	handler := newRPCHandler(t, nil)

	for _, procedure := range []string{authenticatedProcedure, absentProcedure} {
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
			authenticatedProcedure,
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
		infraconnect.Routes(infraconnect.Config{
			Registry:         newRegistry(t),
			Handlers:         nil,
			Audit:            nil,
			TracerProvider:   nil,
			TrustedProxyHops: 0,
		}),
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

func TestPipelineAuditsASuccessfulCall(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t, newGreetHandlers(t), 0)

	res := sendRequest(t, fixture.handler, newConnectRequest(anonymousProcedure))

	if got, want := res.status, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d (body = %q)", got, want, res.body)
	}

	record := singleAuditRecord(t, fixture.audit)

	assertAudit(t, record, map[string]any{
		"method":      anonymousProcedure,
		"result":      "ok",
		"http_status": float64(http.StatusOK),
	})
	assertCorrelated(t, record)
	assertNoCorrelationHeaders(t, res.header)

	if _, reported := record["failure_reason"]; reported {
		t.Errorf("audit.failure_reason = %#v, want it omitted on success", record["failure_reason"])
	}

	if got := len(fixture.spans.Ended()); got != 1 {
		t.Errorf("ended spans = %d, want 1", got)
	}
}

func TestPipelineAuditsARejection(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		procedure string
		header    map[string]string
		want      string
	}{
		"an external token on an anonymous procedure": {
			procedure: anonymousProcedure,
			header:    map[string]string{"Authorization": "Bearer outside"},
			want:      "external_authorization",
		},
		"a workload credential on an anonymous procedure": {
			procedure: anonymousProcedure,
			header:    map[string]string{"Workload-Authorization": "Bearer inside"},
			want:      "workload_authorization",
		},
		"an authenticated procedure without credentials": {
			procedure: authenticatedProcedure,
			header:    nil,
			want:      "anonymous_rejected",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mounted := &counter{calls: 0}
			fixture := newFixture(t, map[string]http.Handler{greetMountPath: mounted}, 0)

			req := newConnectRequest(test.procedure)
			for key, value := range test.header {
				req.Header.Set(key, value)
			}

			res := sendRequest(t, fixture.handler, req)

			if got, want := res.status, http.StatusUnauthorized; got != want {
				t.Errorf("status = %d, want %d", got, want)
			}

			if mounted.calls != 0 {
				t.Errorf("mounted handler calls = %d, want 0", mounted.calls)
			}

			record := singleAuditRecord(t, fixture.audit)

			assertAudit(t, record, map[string]any{
				"method":         test.procedure,
				"result":         "unauthenticated",
				"failure_reason": test.want,
				"http_status":    float64(http.StatusUnauthorized),
			})
			assertCorrelated(t, record)
			assertNoCorrelationHeaders(t, res.header)
		})
	}
}

func TestPipelineAuditsACallWhoseHandlerPanics(t *testing.T) {
	t.Parallel()

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	fixture := newFixture(t, map[string]http.Handler{greetMountPath: panicking}, 0)

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Error("the panic of the mounted handler did not propagate")
			}
		}()

		fixture.handler.ServeHTTP(httptest.NewRecorder(), newConnectRequest(anonymousProcedure))
	}()

	record := singleAuditRecord(t, fixture.audit)

	assertAudit(t, record, map[string]any{
		"method": anonymousProcedure,
		"result": "unknown",
	})
	assertCorrelated(t, record)
}

func TestPipelineLeavesUnroutedRequestsOutOfTheAudit(t *testing.T) {
	t.Parallel()

	tests := map[string]*http.Request{
		"an unregistered procedure": newConnectRequest(absentProcedure),
		"a GET request":             httptest.NewRequest(http.MethodGet, "/favicon.ico", nil),
		"a request no RPC protocol uses": httptest.NewRequest(
			http.MethodPost,
			anonymousProcedure,
			strings.NewReader("hello"),
		),
	}

	tests["a request no RPC protocol uses"].Header.Set("Content-Type", "text/plain")

	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newFixture(t, map[string]http.Handler{greetMountPath: &counter{calls: 0}}, 0)

			res := sendRequest(t, fixture.handler, req)

			if got := auditRecords(t, fixture.audit); len(got) != 0 {
				t.Errorf("audit records = %v, want none", got)
			}

			if got := len(fixture.spans.Ended()); got != 0 {
				t.Errorf("ended spans = %d, want 0", got)
			}

			assertNoCorrelationHeaders(t, res.header)
		})
	}
}

func TestPipelineStartsItsOwnTrace(t *testing.T) {
	t.Parallel()

	fixture := newFixture(t, newGreetHandlers(t), 0)

	req := newConnectRequest(anonymousProcedure)
	req.Header.Set("Traceparent", clientTraceparent)

	res := sendRequest(t, fixture.handler, req)

	if got, want := res.status, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d (body = %q)", got, want, res.body)
	}

	record := singleAuditRecord(t, fixture.audit)

	assertCorrelated(t, record)

	if got := record["trace_id"]; got == clientTraceID {
		t.Errorf("audit.trace_id = %v, want it not to follow the trace context of the client", got)
	}

	ended := fixture.spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(ended))
	}

	if parent := ended[0].Parent(); parent.IsValid() {
		t.Errorf("span parent = %v, want the span to be a root", parent)
	}

	if got, want := ended[0].Name(), strings.TrimPrefix(anonymousProcedure, "/"); got != want {
		t.Errorf("span name = %q, want %q", got, want)
	}
}

func TestPipelineKeepsCredentialsOutOfTheLogs(t *testing.T) {
	const marker = "audit-marker-value"

	var processLogs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(logging.NewLogger(&processLogs, logging.Options{Level: slog.LevelDebug, AddSource: false, ProjectID: ""}))
	t.Cleanup(func() { slog.SetDefault(previous) })

	fixture := newFixture(t, newGreetHandlers(t), 0)

	req := newConnectRequest(anonymousProcedure)
	req.Header.Set("Authorization", "Bearer "+marker)

	res := sendRequest(t, fixture.handler, req)

	if got, want := res.status, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}

	if strings.Contains(fixture.audit.String(), marker) {
		t.Errorf("audit log = %q, want it without the credential", fixture.audit.String())
	}

	if strings.Contains(processLogs.String(), marker) {
		t.Errorf("log = %q, want it without the credential", processLogs.String())
	}

	if !strings.Contains(processLogs.String(), "rpc request rejected") {
		t.Errorf("log = %q, want the rejection recorded", processLogs.String())
	}
}

func TestSourceIPFollowsTheTrustedProxyHops(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		hops       int
		remoteAddr string
		forwarded  []string
		want       string
	}{
		"no trusted hop takes the peer": {
			hops:       0,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.9"},
			want:       "192.0.2.1",
		},
		"one trusted hop takes the rightmost value": {
			hops:       1,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.9"},
			want:       "203.0.113.9",
		},
		"two trusted hops take the second value from the right": {
			hops:       2,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.9"},
			want:       "198.51.100.7",
		},
		"several header lines are read in order": {
			hops:       2,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7", "203.0.113.9"},
			want:       "198.51.100.7",
		},
		"surrounding spaces are trimmed": {
			hops:       1,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"  198.51.100.7  ,  203.0.113.9  "},
			want:       "203.0.113.9",
		},
		"too few values fall back to the peer": {
			hops:       3,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.9"},
			want:       "192.0.2.1",
		},
		"a value that is not an address falls back to the peer": {
			hops:       1,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7, unknown"},
			want:       "192.0.2.1",
		},
		"an IPv6 value is taken as it is": {
			hops:       1,
			remoteAddr: "192.0.2.1:1234",
			forwarded:  []string{"198.51.100.7, 2001:db8::1"},
			want:       "2001:db8::1",
		},
		"a peer address without a port is taken whole": {
			hops:       0,
			remoteAddr: "192.0.2.1",
			forwarded:  nil,
			want:       "192.0.2.1",
		},
		"no forwarded header falls back to the peer": {
			hops:       1,
			remoteAddr: "[2001:db8::2]:1234",
			forwarded:  nil,
			want:       "2001:db8::2",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture := newFixture(t, map[string]http.Handler{greetMountPath: &counter{calls: 0}}, test.hops)

			req := newConnectRequest(anonymousProcedure)
			req.RemoteAddr = test.remoteAddr

			for _, value := range test.forwarded {
				req.Header.Add("X-Forwarded-For", value)
			}

			sendRequest(t, fixture.handler, req)

			assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{"source_ip": test.want})
		})
	}
}
