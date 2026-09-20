package forward

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/connecterr"
)

const defaultUpstreamTimeout = 30 * time.Second

var (
	errUpstreamUnavailable = errors.New("upstream unavailable")
	errCanceled            = errors.New("canceled")
	errDeadlineExceeded    = errors.New("deadline exceeded")
)

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
		return connectrpc.NewError(connectrpc.CodeCanceled, errCanceled)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return connectrpc.NewError(connectrpc.CodeDeadlineExceeded, errDeadlineExceeded)
	}

	var upstream *connectrpc.Error
	if !errors.As(err, &upstream) {
		slog.ErrorContext(ctx, "upstream call failed", "error", err)

		return connectrpc.NewError(connectrpc.CodeUnavailable, errUpstreamUnavailable)
	}

	if upstream.Code() == connectrpc.CodeCanceled {
		return connectrpc.NewError(connectrpc.CodeCanceled, errCanceled)
	}

	if upstream.Code() == connectrpc.CodeDeadlineExceeded {
		return connectrpc.NewError(connectrpc.CodeDeadlineExceeded, errDeadlineExceeded)
	}

	if !connectrpc.IsWireError(upstream) {
		slog.ErrorContext(ctx, "upstream is unreachable", "error", err)

		return connectrpc.NewError(connectrpc.CodeUnavailable, errUpstreamUnavailable)
	}

	if upstream.Code() == connectrpc.CodeUnknown || upstream.Code() == connectrpc.CodeInternal { //nolint:forbidigo // reading the upstream code, not building an internal error
		return connecterr.InternalError(ctx, err)
	}

	return relayedError(upstream)
}

func relayedError(upstream *connectrpc.Error) *connectrpc.Error {
	relayed := connectrpc.NewError(upstream.Code(), errors.New(upstream.Message()))

	for _, detail := range upstream.Details() {
		relayed.AddDetail(detail)
	}

	return relayed
}
