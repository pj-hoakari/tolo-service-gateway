package connect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	connectrpc "connectrpc.com/connect"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/connecterr"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forward"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	resultUnknown     = "unknown"
	resultInternal    = "internal"
	reasonIssueFailed = "issue_failed"
	tracerName        = "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
)

var (
	errMissingIssuer       = errors.New("connect: no internal JWT issuer is configured")
	errUnexpectedRejection = errors.New("connect: unexpected rejection code")
)

type EntryIssuer interface {
	IssueFromExternal(ctx context.Context, input issuer.ExternalTokenInput) (issuer.Issued, error)
}

type Config struct {
	Registry         *registry.Registry
	Handlers         map[string]http.Handler
	Audit            *audit.Emitter
	Authenticator    *authn.Authenticator
	Issuer           EntryIssuer
	TracerProvider   trace.TracerProvider
	TrustedProxyHops int
}

func Routes(cfg Config) func(mux *http.ServeMux) {
	errorWriter := connectrpc.NewErrorWriter()
	unimplemented := newUnimplementedHandler(errorWriter)
	tracer := tracerOf(cfg.TracerProvider)

	if cfg.Authenticator == nil {
		cfg.Authenticator = authn.NewAuthenticator(nil, nil)
	}

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
	result, rejection := p.config.Authenticator.Authenticate(r.Context(), r.Header, entry)

	if rejection != nil {
		p.reject(w, r, entry, record, result, rejection)

		return
	}

	if result.External == nil {
		p.next.ServeHTTP(w, r)

		return
	}

	issued, err := p.issue(r.Context(), entry, *result.External)
	if err != nil {
		record.Result = resultInternal
		record.FailureReason = reasonIssueFailed

		p.writeError(w, r, connecterr.InternalError(r.Context(), err))

		return
	}

	recordExternal(record, *result.External)

	record.Txn = issued.Claims.Txn
	record.IssuedJTI = issued.Claims.ID

	p.next.ServeHTTP(w, r.WithContext(forward.ContextWithInternalToken(r.Context(), issued.Token)))
}

func (p *pipeline) reject(
	w http.ResponseWriter,
	r *http.Request,
	entry registry.Entry,
	record *audit.Record,
	result authn.Result,
	rejection *authn.Rejection,
) {
	slog.WarnContext(r.Context(), "rpc request rejected", "procedure", entry.Procedure, "reason", rejection.Reason)

	if result.External != nil {
		recordExternal(record, *result.External)
	}

	err := rejectionError(r.Context(), rejection.Code)

	record.Result = err.Code().String()
	record.FailureReason = rejection.Reason

	p.writeError(w, r, err)
}

func rejectionError(ctx context.Context, code connectrpc.Code) *connectrpc.Error {
	if code == connectrpc.CodePermissionDenied {
		return connecterr.PermissionDenied()
	}

	if code == connectrpc.CodeUnavailable {
		return connecterr.AuthenticationUnavailable()
	}

	if code == connectrpc.CodeUnauthenticated {
		return connecterr.Unauthenticated()
	}

	return connecterr.InternalError(ctx, fmt.Errorf("%w: %s", errUnexpectedRejection, code))
}

func (p *pipeline) issue(ctx context.Context, entry registry.Entry, token authn.ExternalToken) (issuer.Issued, error) {
	var zero issuer.Issued

	if p.config.Issuer == nil {
		return zero, errMissingIssuer
	}

	issued, err := p.config.Issuer.IssueFromExternal(ctx, issuer.ExternalTokenInput{
		Audience:        entry.Destination,
		TokenUse:        token.TokenUse,
		Subject:         token.Subject,
		ClientID:        token.ClientID,
		Scope:           token.Scope,
		SourceJTI:       token.JTI,
		SourceExpiresAt: token.ExpiresAt,
		TenantPublicID:  token.TenantID,
		EventPublicID:   token.EventID,
	})
	if err != nil {
		return zero, fmt.Errorf("issue the internal JWT: %w", err)
	}

	return issued, nil
}

func recordExternal(record *audit.Record, token authn.ExternalToken) {
	record.ClientID = token.ClientID
	record.Subject = token.Subject
	record.TokenUse = token.TokenUse
	record.SourceJTI = token.JTI
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
