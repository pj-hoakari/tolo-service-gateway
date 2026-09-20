package connecterr_test

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

	"github.com/pj-hoakari/tolo-service-gateway/internal/connecterr"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
)

func TestInternalErrorHidesDetail(t *testing.T) {
	logs := captureLog(t)

	ctx := withSampledSpan(t, context.Background())

	err := connecterr.InternalError(ctx, errors.New("secret detail"))
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeInternal; got != want {
		t.Fatalf("InternalError() code = %v, want %v", got, want)
	}

	if got, want := err.Message(), "internal error"; got != want {
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

	for _, key := range []string{"logging.googleapis.com/trace", "logging.googleapis.com/spanId"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("log entry = %v, want it to name %q", entry, key)
		}
	}
}

func TestCanceledRequestIsNotLogged(t *testing.T) {
	logs := captureLog(t)

	err := connecterr.InternalError(context.Background(), context.Canceled)
	if got, want := connectrpc.CodeOf(err), connectrpc.CodeCanceled; got != want {
		t.Fatalf("InternalError() code = %v, want %v", got, want)
	}

	if logs.Len() != 0 {
		t.Errorf("log = %q, want nothing logged", logs.String())
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var logs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(logging.NewLogger(&logs, logging.Options{Level: slog.LevelDebug, AddSource: false, ProjectID: ""}))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return &logs
}

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
