package audit

import (
	"context"
	"log/slog"
)

const (
	groupKey         = "audit"
	keyMethod        = "method"
	keyClientID      = "client_id"
	keySubject       = "sub"
	keyTokenUse      = "token_use"
	keyTxn           = "txn"
	keyIssuedJTI     = "jti"
	keySourceJTI     = "src_jti"
	keyOriginSubject = "origin_sub"
	keyResult        = "result"
	keyFailureReason = "failure_reason"
	keySourceIP      = "source_ip"
	keyHTTPStatus    = "http_status"
	keyTraceID       = "trace_id"
	keySpanID        = "span_id"
)

type Record struct {
	Procedure     string
	SourceIP      string
	ClientID      string
	Subject       string
	TokenUse      string
	Txn           string
	IssuedJTI     string
	SourceJTI     string
	OriginSubject string
	Result        string
	FailureReason string
	HTTPStatus    int
	TraceID       string
	SpanID        string
}

type contextKey struct{}

func NewContext(ctx context.Context, record *Record) context.Context {
	return context.WithValue(ctx, contextKey{}, record)
}

func FromContext(ctx context.Context) *Record {
	record, ok := ctx.Value(contextKey{}).(*Record)
	if !ok {
		return nil
	}

	return record
}

type Emitter struct {
	logger *slog.Logger
}

func NewEmitter(logger *slog.Logger) *Emitter {
	return &Emitter{logger: logger}
}

func (e *Emitter) Emit(ctx context.Context, record *Record) {
	if e == nil || e.logger == nil || record == nil {
		return
	}

	e.logger.LogAttrs(ctx, slog.LevelInfo, groupKey, slog.Attr{
		Key:   groupKey,
		Value: slog.GroupValue(record.attrs()...),
	})
}

func (r *Record) attrs() []slog.Attr {
	attrs := []slog.Attr{slog.String(keyMethod, r.Procedure)}

	optional := []slog.Attr{
		slog.String(keyClientID, r.ClientID),
		slog.String(keySubject, r.Subject),
		slog.String(keyTokenUse, r.TokenUse),
		slog.String(keyTxn, r.Txn),
		slog.String(keyIssuedJTI, r.IssuedJTI),
		slog.String(keySourceJTI, r.SourceJTI),
		slog.String(keyOriginSubject, r.OriginSubject),
	}

	for _, attr := range optional {
		if attr.Value.String() != "" {
			attrs = append(attrs, attr)
		}
	}

	attrs = append(attrs, slog.String(keyResult, r.Result))

	if r.FailureReason != "" {
		attrs = append(attrs, slog.String(keyFailureReason, r.FailureReason))
	}

	attrs = append(attrs,
		slog.String(keySourceIP, r.SourceIP),
		slog.Int(keyHTTPStatus, r.HTTPStatus),
	)

	if r.TraceID != "" {
		attrs = append(attrs, slog.String(keyTraceID, r.TraceID))
	}

	if r.SpanID != "" {
		attrs = append(attrs, slog.String(keySpanID, r.SpanID))
	}

	return attrs
}
