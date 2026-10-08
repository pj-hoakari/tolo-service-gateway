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
	"github.com/pj-hoakari/tolo-service-gateway/internal/config"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/connecterr"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forward"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
	"github.com/pj-hoakari/tolo-service-gateway/internal/reissue"
)

const (
	resultUnknown         = "unknown"
	reasonIssueFailed     = "issue_failed"
	reasonEdgeNotAllowed  = "edge_not_allowed"
	reasonContextRequired = "context_required"
	tracerName            = "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
)

var (
	errMissingIssuer       = errors.New("connect: no internal JWT issuer is configured")
	errUnexpectedRejection = errors.New("connect: unexpected rejection code")
)

type EntryIssuer interface {
	IssueFromExternal(ctx context.Context, input issuer.ExternalTokenInput) (issuer.Issued, error)
}

type Config struct {
	Inbound          config.Inbound
	Registry         *registry.Registry
	Handlers         map[string]http.Handler
	Audit            *audit.Emitter
	Authenticator    *authn.Authenticator
	Issuer           EntryIssuer
	Reissuer         *reissue.Reissuer
	TracerProvider   trace.TracerProvider
	TrustedProxyHops int
}

func Routes(cfg Config) func(mux *http.ServeMux) {
	errorWriter := connectrpc.NewErrorWriter()
	unimplemented := newUnimplementedHandler(errorWriter)
	tracer := tracerOf(cfg.TracerProvider)

	admit := cfg.admission()

	return func(mux *http.ServeMux) {
		for _, path := range slices.Sorted(maps.Keys(cfg.Handlers)) {
			mux.Handle(path, &pipeline{
				config:      cfg,
				admit:       admit,
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

type admission func(ctx context.Context, header http.Header, entry registry.Entry, record *audit.Record) (string, *connectrpc.Error)

func (cfg Config) admission() admission {
	switch cfg.Inbound {
	case config.InboundPublic:
		authenticator := cfg.Authenticator
		if authenticator == nil {
			authenticator = authn.NewAuthenticator(nil, nil)
		}

		return publicAdmission{authenticator: authenticator, issuer: cfg.Issuer}.admit
	case config.InboundInternal:
		return serviceAdmission{reissuer: cfg.Reissuer}.admit
	default:
		panic(fmt.Sprintf("connect: unknown inbound %q", cfg.Inbound))
	}
}

type pipeline struct {
	config      Config
	admit       admission
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
		CallerService: "",
		Origin:        "",
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
	token, rejection := p.admit(r.Context(), r.Header, entry, record)
	if rejection != nil {
		slog.WarnContext(r.Context(), "rpc request rejected", "procedure", entry.Procedure, "reason", record.FailureReason)

		record.Result = rejection.Code().String()

		p.writeError(w, r, rejection)

		return
	}

	if token != "" {
		r = r.WithContext(forward.ContextWithInternalToken(r.Context(), token))
	}

	p.next.ServeHTTP(w, r)
}

type serviceAdmission struct {
	reissuer *reissue.Reissuer
}

func (a serviceAdmission) admit(ctx context.Context, header http.Header, entry registry.Entry, record *audit.Record) (string, *connectrpc.Error) {
	credential, rejection := authn.ServiceCall(header)
	if rejection != nil {
		record.FailureReason = rejection.Reason

		return "", rejectionError(ctx, rejection.Code)
	}

	result, err := a.reissuer.Reissue(ctx, reissue.Request{
		Caller:       credential.Caller,
		Procedure:    entry.Procedure,
		ContextToken: credential.ContextToken,
	})
	if err != nil {
		if !errors.Is(err, reissue.ErrInvalidContext) {
			record.CallerService = credential.Caller
		}

		return "", reissueRejection(ctx, err, record)
	}

	claims := result.Issued.Claims

	record.CallerService = credential.Caller
	record.Origin = string(result.Origin)
	record.ClientID = claims.ClientID
	record.Subject = claims.Subject
	record.TokenUse = claims.TokenUse
	record.Txn = claims.Txn
	record.IssuedJTI = claims.ID
	record.SourceJTI = claims.SourceJTI
	record.OriginSubject = claims.OriginSub

	return result.Issued.Token, nil
}

func reissueRejection(ctx context.Context, err error, record *audit.Record) *connectrpc.Error {
	switch {
	case errors.Is(err, reissue.ErrEdgeNotAllowed):
		record.FailureReason = reasonEdgeNotAllowed

		return connecterr.PermissionDenied()
	case errors.Is(err, reissue.ErrContextRequired):
		record.FailureReason = reasonContextRequired

		return connecterr.Unauthenticated()
	case errors.Is(err, reissue.ErrInvalidContext):
		record.FailureReason = authn.ReasonInvalidContext

		return connecterr.Unauthenticated()
	default:
		record.FailureReason = reasonIssueFailed

		return connecterr.InternalError(ctx, err)
	}
}

type publicAdmission struct {
	authenticator *authn.Authenticator
	issuer        EntryIssuer
}

func (a publicAdmission) admit(ctx context.Context, header http.Header, entry registry.Entry, record *audit.Record) (string, *connectrpc.Error) {
	result, rejection := a.authenticator.Authenticate(ctx, header, entry)
	if rejection != nil {
		if result.External != nil {
			recordExternal(record, *result.External)
		}

		record.FailureReason = rejection.Reason

		return "", rejectionError(ctx, rejection.Code)
	}

	if result.External == nil {
		return "", nil
	}

	issued, err := a.issue(ctx, entry, *result.External)
	if err != nil {
		record.FailureReason = reasonIssueFailed

		return "", connecterr.InternalError(ctx, err)
	}

	recordExternal(record, *result.External)

	record.Txn = issued.Claims.Txn
	record.IssuedJTI = issued.Claims.ID

	return issued.Token, nil
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

func (a publicAdmission) issue(ctx context.Context, entry registry.Entry, token authn.ExternalToken) (issuer.Issued, error) {
	var zero issuer.Issued

	if a.issuer == nil {
		return zero, errMissingIssuer
	}

	issued, err := a.issuer.IssueFromExternal(ctx, issuer.ExternalTokenInput{
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
