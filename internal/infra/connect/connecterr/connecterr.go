package connecterr

import (
	"context"
	"errors"
	"log/slog"

	connectrpc "connectrpc.com/connect"
)

// errInternal is the only detail a client learns about an internal failure.
var errInternal = errors.New("internal error")

var (
	errUnauthenticated           = errors.New("unauthenticated")
	errPermissionDenied          = errors.New("permission denied")
	errUnimplemented             = errors.New("unimplemented")
	errUpstreamUnavailable       = errors.New("upstream unavailable")
	errAuthenticationUnavailable = errors.New("authentication unavailable")
	errCanceled                  = errors.New("canceled")
	errDeadlineExceeded          = errors.New("deadline exceeded")
)

func Unauthenticated() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnauthenticated, errUnauthenticated)
}

func PermissionDenied() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodePermissionDenied, errPermissionDenied)
}

func Unimplemented() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnimplemented, errUnimplemented)
}

func Unavailable() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnavailable, errUpstreamUnavailable)
}

func AuthenticationUnavailable() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeUnavailable, errAuthenticationUnavailable)
}

func Canceled() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeCanceled, errCanceled)
}

func DeadlineExceeded() *connectrpc.Error {
	return connectrpc.NewError(connectrpc.CodeDeadlineExceeded, errDeadlineExceeded)
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
		return connectrpc.NewError(connectrpc.CodeCanceled, err)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return connectrpc.NewError(connectrpc.CodeDeadlineExceeded, err)
	}

	slog.ErrorContext(ctx, "internal error", "error", err)

	return connectrpc.NewError(connectrpc.CodeInternal, errInternal) //nolint:forbidigo // the one place that builds internal errors
}
