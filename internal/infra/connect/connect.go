package connect

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	connectrpc "connectrpc.com/connect"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/connecterr"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	resultUnknown = "unknown"
	tracerName    = "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
)

type Config struct {
	Registry         *registry.Registry
	Handlers         map[string]http.Handler
	Audit            *audit.Emitter
	TracerProvider   trace.TracerProvider
	TrustedProxyHops int
}

func Routes(cfg Config) func(mux *http.ServeMux) {
	errorWriter := connectrpc.NewErrorWriter()
	unimplemented := newUnimplementedHandler(errorWriter)
	tracer := tracerOf(cfg.TracerProvider)

	return func(mux *http.ServeMux) {
		for _, path := range slices.Sorted(maps.Keys(cfg.Handlers)) {
			mux.Handle(path, &pipeline{
				config:      cfg,
				tracer:      tracer,
				next:        cfg.Handlers[path],
				fallback:    unimplemented,
				errorWriter: errorWriter,
			})
		}

		mux.Handle("/", unimplemented)
	}
}

func tracerOf(provider trace.TracerProvider) trace.Tracer {
	if provider == nil {
		return noop.NewTracerProvider().Tracer(tracerName)
	}

	return provider.Tracer(tracerName)
}

type pipeline struct {
	config      Config
	tracer      trace.Tracer
	next        http.Handler
	fallback    http.Handler
	errorWriter *connectrpc.ErrorWriter
}

func (p *pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	entry, registered := p.classify(r)
	if !registered {
		p.fallback.ServeHTTP(w, r)

		return
	}

	ctx, span := p.tracer.Start(
		r.Context(),
		strings.TrimPrefix(entry.Procedure, "/"),
		trace.WithNewRoot(),
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	record := newRecord(entry, sourceIP(r, p.config.TrustedProxyHops), span.SpanContext())

	ctx = audit.NewContext(ctx, record)
	r = r.WithContext(ctx)

	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK, written: false}

	defer p.finish(ctx, span, recorder, record)

	p.serve(recorder, r, entry, record)
}

func (p *pipeline) finish(ctx context.Context, span trace.Span, recorder *statusRecorder, record *audit.Record) {
	record.HTTPStatus = recorder.status

	if record.Result == "" {
		record.Result = resultUnknown
	}

	if record.Result != resultOK {
		span.SetStatus(codes.Error, record.Result)
	}

	p.config.Audit.Emit(ctx, record)
}

func newRecord(entry registry.Entry, sourceIP string, spanContext trace.SpanContext) *audit.Record {
	record := &audit.Record{
		Procedure:     entry.Procedure,
		SourceIP:      sourceIP,
		ClientID:      "",
		Subject:       "",
		TokenUse:      "",
		Txn:           "",
		IssuedJTI:     "",
		SourceJTI:     "",
		OriginSubject: "",
		Result:        "",
		FailureReason: "",
		HTTPStatus:    0,
		TraceID:       "",
		SpanID:        "",
	}

	if spanContext.IsValid() {
		record.TraceID = spanContext.TraceID().String()
		record.SpanID = spanContext.SpanID().String()
	}

	return record
}

func (p *pipeline) serve(w http.ResponseWriter, r *http.Request, entry registry.Entry, record *audit.Record) {
	reason, rejected := authn.Reject(r.Header, entry)
	if !rejected {
		p.next.ServeHTTP(w, r)

		return
	}

	slog.WarnContext(r.Context(), "rpc request rejected", "procedure", entry.Procedure, "reason", reason)

	record.Result = connectrpc.CodeUnauthenticated.String()
	record.FailureReason = reason

	p.writeError(w, r, connecterr.Unauthenticated())
}

func (p *pipeline) classify(r *http.Request) (registry.Entry, bool) {
	if r.Method != http.MethodPost || !p.errorWriter.IsSupported(r) {
		var zero registry.Entry

		return zero, false
	}

	return p.config.Registry.Lookup(r.URL.Path)
}

func (p *pipeline) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if writeErr := p.errorWriter.Write(w, r, err); writeErr != nil {
		slog.ErrorContext(r.Context(), "rpc error response write failed", "error", writeErr)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(status int) {
	if !s.written {
		s.status = status
		s.written = true
	}

	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true

	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func newUnimplementedHandler(errorWriter *connectrpc.ErrorWriter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleUnimplemented(w, r, errorWriter)
	})
}

func handleUnimplemented(w http.ResponseWriter, r *http.Request, errorWriter *connectrpc.ErrorWriter) {
	if r.Method != http.MethodPost || !errorWriter.IsSupported(r) {
		http.NotFound(w, r)

		return
	}

	err := errorWriter.Write(w, r, connecterr.Unimplemented())
	if err != nil {
		slog.ErrorContext(r.Context(), "fallback response write failed", "error", err)
	}
}
