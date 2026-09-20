package forward

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/connecterr"
)

const defaultUpstreamTimeout = 30 * time.Second

const (
	reasonUpstreamUnreachable           = "upstream_unreachable"
	reasonUpstreamInternal              = "upstream_internal"
	reasonUpstreamError                 = "upstream_error"
	reasonUpstreamRefused               = "upstream_refused"
	reasonUpstreamRejectedInternalToken = "upstream_rejected_internal_token"
	reasonCanceled                      = "canceled"
	reasonDeadlineExceeded              = "deadline_exceeded"
)

const authorizationHeader = "Authorization"

type internalTokenKey struct{}

func ContextWithInternalToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, internalTokenKey{}, token)
}

func internalTokenFrom(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(internalTokenKey{}).(string)

	return token, ok
}

func AuthorizationInterceptor() connectrpc.Interceptor {
	return connectrpc.UnaryInterceptorFunc(func(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
		return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
			if token, ok := internalTokenFrom(ctx); ok {
				req.Header().Set(authorizationHeader, "Bearer "+token)
			}

			return next(ctx, req)
		}
	})
}

type Mount struct {
	Service string
	New     func(
		httpClient connectrpc.HTTPClient,
		baseURL string,
		clientOptions []connectrpc.ClientOption,
		handlerOptions []connectrpc.HandlerOption,
	) (string, http.Handler)
}

func NewHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func Unary[Req, Res any](
	ctx context.Context,
	req *connectrpc.Request[Req],
	call func(context.Context, *connectrpc.Request[Req]) (*connectrpc.Response[Res], error),
) (*connectrpc.Response[Res], error) {
	ctx, cancel := withUpstreamDeadline(ctx)
	defer cancel()

	res, err := call(ctx, connectrpc.NewRequest(req.Msg))
	if err != nil {
		return nil, translateError(ctx, err)
	}

	return connectrpc.NewResponse(res.Msg), nil
}

func withUpstreamDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}

	return context.WithTimeout(ctx, defaultUpstreamTimeout)
}

func translateError(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) {
		return failed(ctx, reasonCanceled, connecterr.Canceled())
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return failed(ctx, reasonDeadlineExceeded, connecterr.DeadlineExceeded())
	}

	var upstream *connectrpc.Error
	if !errors.As(err, &upstream) {
		slog.ErrorContext(ctx, "upstream call failed", "error", err)

		return failed(ctx, reasonUpstreamUnreachable, connecterr.Unavailable())
	}

	if upstream.Code() == connectrpc.CodeCanceled {
		return failed(ctx, reasonCanceled, connecterr.Canceled())
	}

	if upstream.Code() == connectrpc.CodeDeadlineExceeded {
		return failed(ctx, reasonDeadlineExceeded, connecterr.DeadlineExceeded())
	}

	if !connectrpc.IsWireError(upstream) {
		slog.ErrorContext(ctx, "upstream is unreachable", "error", err)

		return failed(ctx, reasonUpstreamUnreachable, connecterr.Unavailable())
	}

	if upstream.Code() == connectrpc.CodeUnauthenticated && hasInternalToken(ctx) {
		return failed(ctx, reasonUpstreamRejectedInternalToken, connecterr.InternalError(ctx, err))
	}

	if upstream.Code() == connectrpc.CodeUnknown || upstream.Code() == connectrpc.CodeInternal { //nolint:forbidigo // reading the upstream code, not building an internal error
		return failed(ctx, reasonUpstreamInternal, connecterr.InternalError(ctx, err))
	}

	return failed(ctx, relayedReason(upstream.Code()), relayedError(upstream))
}

func relayedReason(code connectrpc.Code) string {
	if slices.Contains(refusalCodes(), code) {
		return reasonUpstreamRefused
	}

	return reasonUpstreamError
}

func refusalCodes() []connectrpc.Code {
	return []connectrpc.Code{
		connectrpc.CodeInvalidArgument,
		connectrpc.CodeNotFound,
		connectrpc.CodeAlreadyExists,
		connectrpc.CodePermissionDenied,
		connectrpc.CodeFailedPrecondition,
		connectrpc.CodeOutOfRange,
		connectrpc.CodeAborted,
		connectrpc.CodeUnauthenticated,
	}
}

func hasInternalToken(ctx context.Context) bool {
	_, ok := internalTokenFrom(ctx)

	return ok
}

func failed(ctx context.Context, reason string, err *connectrpc.Error) error {
	if record := audit.FromContext(ctx); record != nil {
		record.FailureReason = reason
	}

	return err
}

func relayedError(upstream *connectrpc.Error) *connectrpc.Error {
	relayed := connectrpc.NewError(upstream.Code(), errors.New(upstream.Message()))

	for _, detail := range upstream.Details() {
		relayed.AddDetail(detail)
	}

	return relayed
}
