package connecterr

import (
	"context"
	"errors"
	"log/slog"

	connectrpc "connectrpc.com/connect/v2"
)

// messageInternal is the only detail a client learns about an internal failure.
const messageInternal = "internal error"

const (
	messageUnauthenticated           = "unauthenticated"
	messagePermissionDenied          = "permission denied"
	messageUnimplemented             = "unimplemented"
	messageUpstreamUnavailable       = "upstream unavailable"
	messageAuthenticationUnavailable = "authentication unavailable"
	messageCanceled                  = "canceled"
	messageDeadlineExceeded          = "deadline exceeded"
)

func Unauthenticated() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnauthenticated, messageUnauthenticated)
}

func PermissionDenied() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodePermissionDenied, messagePermissionDenied)
}

func Unimplemented() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnimplemented, messageUnimplemented)
}

func Unavailable() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnavailable, messageUpstreamUnavailable)
}

func AuthenticationUnavailable() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnavailable, messageAuthenticationUnavailable)
}

func Canceled() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeCanceled, messageCanceled)
}

func DeadlineExceeded() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeDeadlineExceeded, messageDeadlineExceeded)
}

// InternalError reports a failure the client can do nothing about. The cause is
// written to the server log and replaced by a fixed message, so that no
// internal detail leaves the service. The log handler names the trace of the
// request context on the record, so an operator can find the failure in the
// trace it belongs to.
//
// A cancelled or timed-out request is the client going away rather than a
// server fault, so it keeps its own code and is not logged.
//
// It is exported for the other transports of this process, so that every
// service answers an internal failure the same way.
func InternalError(ctx context.Context, err error) *connectrpc.Error {
	if errors.Is(err, context.Canceled) {
		return Canceled().WithCause(err)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return DeadlineExceeded().WithCause(err)
	}

	slog.ErrorContext(ctx, "internal error", "error", err)

	return connectrpc.NewError(connectrpc.CodeInternal, messageInternal) //nolint:forbidigo // the one place that builds internal errors
}
