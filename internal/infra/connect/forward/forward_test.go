package forward_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forward"
)

type pingFunc func(context.Context, *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error)

type stubGreetService struct {
	greetv1connect.UnimplementedGreetServiceHandler
	ping pingFunc
}

func (s stubGreetService) Ping(ctx context.Context, req *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
	return s.ping(ctx, req)
}

func pong() *connectrpc.Response[greetv1.PingResponse] {
	return connectrpc.NewResponse(&greetv1.PingResponse{Message: "pong"})
}

func startUpstream(t *testing.T, ping pingFunc) (greetv1connect.GreetServiceClient, *httptest.Server) {
	t.Helper()

	mux := http.NewServeMux()
	path, handler := greetv1connect.NewGreetServiceHandler(stubGreetService{
		UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{},
		ping:                             ping,
	})
	mux.Handle(path, handler)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := greetv1connect.NewGreetServiceClient(forward.NewHTTPClient(http.DefaultTransport), server.URL)

	return client, server
}

func callPing(ctx context.Context, client greetv1connect.GreetServiceClient, req *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
	return forward.Unary(ctx, req, client.Ping)
}

func TestUnaryReturnsTheUpstreamMessageWithoutItsMetadata(t *testing.T) {
	t.Parallel()

	client, _ := startUpstream(t, func(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
		res := pong()
		res.Header().Set("X-Upstream-Header", "leaked")
		res.Trailer().Set("X-Upstream-Trailer", "leaked")

		return res, nil
	})

	res, err := callPing(t.Context(), client, connectrpc.NewRequest(&greetv1.PingRequest{}))
	if err != nil {
		t.Fatalf("Unary() error = %v, want nil", err)
	}

	if got, want := res.Msg.GetMessage(), "pong"; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}

	if got := len(res.Header()); got != 0 {
		t.Errorf("response headers = %v, want none", res.Header())
	}

	if got := len(res.Trailer()); got != 0 {
		t.Errorf("response trailers = %v, want none", res.Trailer())
	}
}

func TestUnaryDoesNotForwardTheRequestHeaders(t *testing.T) {
	t.Parallel()

	seen := make(chan http.Header, 1)

	client, _ := startUpstream(t, func(_ context.Context, req *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
		seen <- req.Header().Clone()

		return pong(), nil
	})

	req := connectrpc.NewRequest(&greetv1.PingRequest{})
	req.Header().Set("Authorization", "Bearer outside")
	req.Header().Set("X-Request-Id", "outside")

	if _, err := callPing(t.Context(), client, req); err != nil {
		t.Fatalf("Unary() error = %v, want nil", err)
	}

	header := <-seen

	for _, name := range []string{"Authorization", "X-Request-Id"} {
		if _, forwarded := header[http.CanonicalHeaderKey(name)]; forwarded {
			t.Errorf("the upstream saw %s, want it withheld", name)
		}
	}
}

func TestUnaryTranslatesUpstreamErrors(t *testing.T) {
	t.Parallel()

	detail, err := connectrpc.NewErrorDetail(&greetv1.PingResponse{Message: "detail"})
	if err != nil {
		t.Fatalf("NewErrorDetail() error = %v, want nil", err)
	}

	tests := map[string]struct {
		upstream    *connectrpc.Error
		wantCode    connectrpc.Code
		wantMessage string
		wantDetails int
	}{
		"an invalid argument keeps its code, message and details": {
			upstream:    connectrpc.NewError(connectrpc.CodeInvalidArgument, errors.New("name is required")),
			wantCode:    connectrpc.CodeInvalidArgument,
			wantMessage: "name is required",
			wantDetails: 1,
		},
		"a permission denial keeps its code and message": {
			upstream:    connectrpc.NewError(connectrpc.CodePermissionDenied, errors.New("no scope")),
			wantCode:    connectrpc.CodePermissionDenied,
			wantMessage: "no scope",
			wantDetails: 0,
		},
		"an internal failure loses its message": {
			upstream:    connectrpc.NewError(connectrpc.CodeInternal, errors.New("the store rejected the query")), //nolint:forbidigo // the upstream code under test, not an internal error built here
			wantCode:    connectrpc.CodeInternal,                                                                  //nolint:forbidigo // the expected code of the translation
			wantMessage: "internal error",
			wantDetails: 0,
		},
		"an unknown failure loses its message": {
			upstream:    connectrpc.NewError(connectrpc.CodeUnknown, errors.New("panic in the store")),
			wantCode:    connectrpc.CodeInternal, //nolint:forbidigo // the expected code of the translation
			wantMessage: "internal error",
			wantDetails: 0,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			upstream := test.upstream
			upstream.Meta().Set("X-Upstream-Meta", "leaked")

			if test.wantDetails > 0 {
				upstream.AddDetail(detail)
			}

			client, _ := startUpstream(t, func(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
				return nil, upstream
			})

			_, err := callPing(t.Context(), client, connectrpc.NewRequest(&greetv1.PingRequest{}))

			got := connectError(t, err)

			if got.Code() != test.wantCode {
				t.Errorf("code = %v, want %v", got.Code(), test.wantCode)
			}

			if got.Message() != test.wantMessage {
				t.Errorf("message = %q, want %q", got.Message(), test.wantMessage)
			}

			if len(got.Details()) != test.wantDetails {
				t.Errorf("details = %d, want %d", len(got.Details()), test.wantDetails)
			}

			if len(got.Meta()) != 0 {
				t.Errorf("metadata = %v, want none", got.Meta())
			}
		})
	}
}

func TestUnaryAnswersAnUnreachableUpstreamWithUnavailable(t *testing.T) {
	t.Parallel()

	client, server := startUpstream(t, func(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
		return pong(), nil
	})
	server.Close()

	_, err := callPing(t.Context(), client, connectrpc.NewRequest(&greetv1.PingRequest{}))

	got := connectError(t, err)

	if got.Code() != connectrpc.CodeUnavailable {
		t.Errorf("code = %v, want %v", got.Code(), connectrpc.CodeUnavailable)
	}

	if got.Message() != "upstream unavailable" {
		t.Errorf("message = %q, want %q", got.Message(), "upstream unavailable")
	}

	host := strings.TrimPrefix(server.URL, "http://")
	if strings.Contains(got.Error(), host) {
		t.Errorf("error = %q, want it not to name %q", got.Error(), host)
	}
}

func TestUnaryReportsACancelledCallAsCancelled(t *testing.T) {
	t.Parallel()

	released := make(chan struct{})

	client, _ := startUpstream(t, func(ctx context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
		<-released

		return pong(), ctx.Err()
	})

	ctx, cancel := context.WithCancel(t.Context())

	go func() {
		cancel()
		close(released)
	}()

	_, err := callPing(ctx, client, connectrpc.NewRequest(&greetv1.PingRequest{}))

	got := connectError(t, err)

	if got.Code() != connectrpc.CodeCanceled {
		t.Errorf("code = %v, want %v", got.Code(), connectrpc.CodeCanceled)
	}
}

func TestUnaryAppliesADeadlineOnlyWhenTheCallerHasNone(t *testing.T) {
	t.Parallel()

	const callerTimeout = 2 * time.Second

	tests := map[string]struct {
		timeout     time.Duration
		wantAtMost  time.Duration
		wantAtLeast time.Duration
	}{
		"a caller without a deadline gets the default one": {
			timeout:     0,
			wantAtMost:  30 * time.Second,
			wantAtLeast: 25 * time.Second,
		},
		"a caller with a deadline keeps it": {
			timeout:     callerTimeout,
			wantAtMost:  callerTimeout,
			wantAtLeast: 0,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			remaining := make(chan time.Duration, 1)

			client, _ := startUpstream(t, func(ctx context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					remaining <- 0

					return pong(), nil
				}

				remaining <- time.Until(deadline)

				return pong(), nil
			})

			ctx := t.Context()

			if test.timeout > 0 {
				withTimeout, cancel := context.WithTimeout(ctx, test.timeout)
				defer cancel()

				ctx = withTimeout
			}

			if _, err := callPing(ctx, client, connectrpc.NewRequest(&greetv1.PingRequest{})); err != nil {
				t.Fatalf("Unary() error = %v, want nil", err)
			}

			got := <-remaining

			if got > test.wantAtMost {
				t.Errorf("the upstream deadline leaves %v, want at most %v", got, test.wantAtMost)
			}

			if got <= test.wantAtLeast {
				t.Errorf("the upstream deadline leaves %v, want more than %v", got, test.wantAtLeast)
			}
		})
	}
}

func failureReasonOf(t *testing.T, ctx context.Context, client greetv1connect.GreetServiceClient) string {
	t.Helper()

	record := &audit.Record{}

	_, err := callPing(audit.NewContext(ctx, record), client, connectrpc.NewRequest(&greetv1.PingRequest{}))
	if err == nil {
		t.Fatal("Unary() error = nil, want an error")
	}

	return record.FailureReason
}

func TestUnaryNamesTheFailureReasonInTheAuditRecord(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		upstream *connectrpc.Error
		want     string
	}{
		"an internal failure": {
			upstream: connectrpc.NewError(connectrpc.CodeInternal, errors.New("the store rejected the query")), //nolint:forbidigo // the upstream code under test, not an internal error built here
			want:     "upstream_internal",
		},
		"an unknown failure": {
			upstream: connectrpc.NewError(connectrpc.CodeUnknown, errors.New("panic in the store")),
			want:     "upstream_internal",
		},
		"an invalid argument": {
			upstream: connectrpc.NewError(connectrpc.CodeInvalidArgument, errors.New("name is required")),
			want:     "upstream_error",
		},
		"a cancelled upstream": {
			upstream: connectrpc.NewError(connectrpc.CodeCanceled, errors.New("the caller went away")),
			want:     "canceled",
		},
		"an upstream past its deadline": {
			upstream: connectrpc.NewError(connectrpc.CodeDeadlineExceeded, errors.New("too slow")),
			want:     "deadline_exceeded",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client, _ := startUpstream(t, func(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
				return nil, test.upstream
			})

			if got := failureReasonOf(t, t.Context(), client); got != test.want {
				t.Errorf("failure reason = %q, want %q", got, test.want)
			}
		})
	}
}

func TestUnaryNamesAnUnreachableUpstreamInTheAuditRecord(t *testing.T) {
	t.Parallel()

	client, server := startUpstream(t, func(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
		return pong(), nil
	})
	server.Close()

	if got, want := failureReasonOf(t, t.Context(), client), "upstream_unreachable"; got != want {
		t.Errorf("failure reason = %q, want %q", got, want)
	}
}

func TestUnaryLeavesTheAuditRecordAloneWhenThereIsNone(t *testing.T) {
	t.Parallel()

	client, server := startUpstream(t, func(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
		return pong(), nil
	})
	server.Close()

	if _, err := callPing(t.Context(), client, connectrpc.NewRequest(&greetv1.PingRequest{})); err == nil {
		t.Fatal("Unary() error = nil, want an error")
	}
}

func connectError(t *testing.T, err error) *connectrpc.Error {
	t.Helper()

	if err == nil {
		t.Fatal("Unary() error = nil, want an error")
	}

	var got *connectrpc.Error
	if !errors.As(err, &got) {
		t.Fatalf("Unary() error = %v, want a *connect.Error", err)
	}

	return got
}
