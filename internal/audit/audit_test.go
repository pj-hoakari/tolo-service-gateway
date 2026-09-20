package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
)

func emit(t *testing.T, record *audit.Record) map[string]any {
	t.Helper()

	var buf bytes.Buffer

	audit.NewEmitter(logging.NewLogger(&buf, logging.Options{
		Level:     slog.LevelInfo,
		AddSource: false,
		ProjectID: "",
	})).Emit(context.Background(), record)

	line := strings.TrimSpace(buf.String())
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

func auditGroup(t *testing.T, entry map[string]any) map[string]any {
	t.Helper()

	group, ok := entry["audit"].(map[string]any)
	if !ok {
		t.Fatalf("audit = %#v, want a group", entry["audit"])
	}

	return group
}

func TestEmitWritesTheAuditGroup(t *testing.T) {
	t.Parallel()

	entry := emit(t, &audit.Record{
		Procedure:     "/greet.v1.GreetService/Greet",
		SourceIP:      "192.0.2.10",
		ClientID:      "tolo-web",
		Subject:       "user-1",
		TokenUse:      "tenant_access",
		Txn:           "txn-1",
		IssuedJTI:     "jti-1",
		SourceJTI:     "src-jti-1",
		OriginSubject: "user-1",
		Result:        "ok",
		FailureReason: "",
		HTTPStatus:    200,
		TraceID:       "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:        "00f067aa0ba902b7",
	})

	if got, want := entry["message"], "audit"; got != want {
		t.Errorf("message = %v, want %q", got, want)
	}

	if got, want := entry["severity"], "INFO"; got != want {
		t.Errorf("severity = %v, want %q", got, want)
	}

	want := map[string]any{
		"method":      "/greet.v1.GreetService/Greet",
		"client_id":   "tolo-web",
		"sub":         "user-1",
		"token_use":   "tenant_access",
		"txn":         "txn-1",
		"jti":         "jti-1",
		"src_jti":     "src-jti-1",
		"origin_sub":  "user-1",
		"result":      "ok",
		"source_ip":   "192.0.2.10",
		"http_status": float64(200),
		"trace_id":    "4bf92f3577b34da6a3ce929d0e0e4736",
		"span_id":     "00f067aa0ba902b7",
	}

	group := auditGroup(t, entry)

	for key, value := range want {
		if got := group[key]; got != value {
			t.Errorf("audit.%s = %#v, want %#v", key, got, value)
		}
	}

	if _, ok := group["failure_reason"]; ok {
		t.Errorf("audit.failure_reason = %#v, want it omitted when empty", group["failure_reason"])
	}
}

func TestEmitOmitsEmptyItemsAndKeepsTheRequiredOnes(t *testing.T) {
	t.Parallel()

	group := auditGroup(t, emit(t, &audit.Record{
		Procedure:     "/greet.v1.GreetService/Ping",
		SourceIP:      "192.0.2.10",
		ClientID:      "",
		Subject:       "",
		TokenUse:      "",
		Txn:           "",
		IssuedJTI:     "",
		SourceJTI:     "",
		OriginSubject: "",
		Result:        "unauthenticated",
		FailureReason: "external_authorization",
		HTTPStatus:    401,
		TraceID:       "",
		SpanID:        "",
	}))

	required := map[string]any{
		"method":         "/greet.v1.GreetService/Ping",
		"result":         "unauthenticated",
		"failure_reason": "external_authorization",
		"source_ip":      "192.0.2.10",
		"http_status":    float64(401),
	}

	for key, value := range required {
		if got := group[key]; got != value {
			t.Errorf("audit.%s = %#v, want %#v", key, got, value)
		}
	}

	for _, key := range []string{"client_id", "sub", "token_use", "txn", "jti", "src_jti", "origin_sub", "trace_id", "span_id"} {
		if _, ok := group[key]; ok {
			t.Errorf("audit.%s = %#v, want it omitted when empty", key, group[key])
		}
	}
}

func TestEmitIgnoresNothingToRecord(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	emitter := audit.NewEmitter(logging.NewLogger(&buf, logging.Options{
		Level:     slog.LevelInfo,
		AddSource: false,
		ProjectID: "",
	}))

	emitter.Emit(context.Background(), nil)

	var absent *audit.Emitter

	absent.Emit(context.Background(), &audit.Record{})

	if got := buf.String(); got != "" {
		t.Errorf("log = %q, want nothing", got)
	}
}

func TestRecordRoundTripsThroughTheContext(t *testing.T) {
	t.Parallel()

	if got := audit.FromContext(context.Background()); got != nil {
		t.Errorf("FromContext() = %#v, want nil", got)
	}

	record := &audit.Record{}

	if got := audit.FromContext(audit.NewContext(context.Background(), record)); got != record {
		t.Errorf("FromContext() = %#v, want the record that was put in", got)
	}
}
