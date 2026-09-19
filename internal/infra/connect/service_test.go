package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	connectrpc "connectrpc.com/connect"
	"go.opentelemetry.io/otel/trace"

	greetv1 "github.com/pj-hoakari/go-service-template/gen/greet/v1"
	"github.com/pj-hoakari/go-service-template/internal/application"
	"github.com/pj-hoakari/go-service-template/internal/domain"
	"github.com/pj-hoakari/go-service-template/internal/logging"
)

func TestServiceGreet(t *testing.T) {
	t.Parallel()

	service := NewService(application.NewGreetService())

	res, err := service.Greet(context.Background(), connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"}))
	if err != nil {
		t.Fatalf("Greet() error = %v", err)
	}

	if got, want := res.Msg.GetGreeting(), "Hello, Ada!"; got != want {
		t.Errorf("Greeting = %q, want %q", got, want)
	}
}

func TestServiceGreetRejectsMissingName(t *testing.T) {
	t.Parallel()

	service := NewService(application.NewGreetService())

	_, err := service.Greet(context.Background(), connectrpc.NewRequest(&greetv1.GreetRequest{}))
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeInvalidArgument; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}
}

// TestInternalErrorHidesDetail keeps the cause of an internal failure out of
// the response and puts it in the server log instead. It cannot run in
// parallel: it reads the log back through the process-wide default logger.
func TestInternalErrorHidesDetail(t *testing.T) {
	logs := captureLog(t)
	service := NewService(failingGreetService{err: errors.New("secret detail")})

	ctx := withSampledSpan(t, context.Background())

	_, err := service.Greet(ctx, connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"}))
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeInternal; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}

	var connectErr *connectrpc.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("Greet() error = %v, want a Connect error", err)
	}

	if got, want := connectErr.Message(), "internal error"; got != want {
		t.Errorf("Message() = %q, want %q", got, want)
	}

	if strings.Contains(err.Error(), "secret detail") {
		t.Errorf("error = %q, want it to omit the underlying failure", err)
	}

	entry := decodeLogEntry(t, logs)

	if got, want := entry["severity"], "ERROR"; got != want {
		t.Errorf("severity = %v, want %q", got, want)
	}

	if got, want := entry["message"], "internal error"; got != want {
		t.Errorf("message = %v, want %q", got, want)
	}

	if got, want := entry["error"], "secret detail"; got != want {
		t.Errorf("error = %v, want %q", got, want)
	}

	// The trace fields replace the trace_id the log line used to carry: the
	// handler reads them off the request context.
	for _, key := range []string{"logging.googleapis.com/trace", "logging.googleapis.com/spanId"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("log entry = %v, want it to name %q", entry, key)
		}
	}
}

// TestCanceledRequestIsNotLogged pins a client that goes away to canceled: it
// is not a server fault, so nothing is logged. It shares the process-wide
// logger with TestInternalErrorHidesDetail and so cannot run in parallel
// either.
func TestCanceledRequestIsNotLogged(t *testing.T) {
	logs := captureLog(t)
	service := NewService(failingGreetService{err: context.Canceled})

	_, err := service.Greet(context.Background(), connectrpc.NewRequest(&greetv1.GreetRequest{Name: "Ada"}))
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeCanceled; got != want {
		t.Fatalf("Greet() error code = %v, want %v", got, want)
	}

	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing logged", logs.String())
	}
}

// captureLog installs the service's own handler over a buffer as the default
// logger for the duration of the test, so the assertions read the records in
// the shape production writes them. The default logger is process-wide, so a
// test that calls this one must not call t.Parallel().
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(logging.NewLogger(&logs, logging.Options{Level: slog.LevelDebug, AddSource: false, ProjectID: ""}))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return &logs
}

// decodeLogEntry parses the single JSON record the captured log holds.
func decodeLogEntry(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()

	line := strings.TrimSpace(logs.String())
	if line == "" {
		t.Fatal("nothing was logged")
	}

	if strings.Contains(line, "\n") {
		t.Fatalf("log = %q, want a single record", line)
	}

	var entry map[string]any

	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}

	return entry
}

// withSampledSpan returns ctx carrying a valid, sampled span context, as the
// tracing interceptor leaves on a request it has handled.
func withSampledSpan(t *testing.T, ctx context.Context) context.Context {
	t.Helper()

	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatalf("TraceIDFromHex() error = %v", err)
	}

	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatalf("SpanIDFromHex() error = %v", err)
	}

	return trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	}))
}

// failingGreetService is a GreetUseCases whose every call fails with err.
type failingGreetService struct {
	err error
}

func (s failingGreetService) Greet(context.Context, application.GreetInput) (domain.Greeting, error) {
	return domain.Greeting{}, s.err
}
