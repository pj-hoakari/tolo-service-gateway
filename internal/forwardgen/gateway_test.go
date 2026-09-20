package forwardgen_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoregistry"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/forward"
	"github.com/pj-hoakari/tolo-service-gateway/internal/forwardgen"
	"github.com/pj-hoakari/tolo-service-gateway/internal/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

type upstreamGreetService struct {
	greetv1connect.UnimplementedGreetServiceHandler
	records chan time.Duration
}

func (s upstreamGreetService) record(ctx context.Context) {
	remaining := time.Duration(0)

	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}

	s.records <- remaining
}

func (s upstreamGreetService) Ping(ctx context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
	s.record(ctx)

	return connectrpc.NewResponse(&greetv1.PingResponse{Message: "pong"}), nil
}

func (s upstreamGreetService) Greet(ctx context.Context, _ *connectrpc.Request[greetv1.GreetRequest]) (*connectrpc.Response[greetv1.GreetResponse], error) {
	s.record(ctx)

	return connectrpc.NewResponse(&greetv1.GreetResponse{Greeting: "Hello!"}), nil
}

type gatewayFixture struct {
	client     greetv1connect.GreetServiceClient
	gatewayURL string
	upstream   *httptest.Server
	records    chan time.Duration
}

func newGateway(t *testing.T) gatewayFixture {
	t.Helper()

	records := make(chan time.Duration, 8)

	mux := http.NewServeMux()
	path, handler := greetv1connect.NewGreetServiceHandler(upstreamGreetService{
		UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{},
		records:                          records,
	})
	mux.Handle(path, handler)

	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	handlers, err := forward.Handlers(
		catalog.Bindings(),
		destinationsTo(t, upstream.URL),
		forwardgen.Mounts(),
		forward.NewHTTPClient(http.DefaultTransport),
		nil,
	)
	if err != nil {
		t.Fatalf("Handlers() error = %v, want nil", err)
	}

	gateway := httptest.NewServer(httpapi.NewHandler(
		httpapi.RPCRoutes(built, handlers),
		httpapi.FallbackRoutes(),
	))
	t.Cleanup(gateway.Close)

	return gatewayFixture{
		client:     greetv1connect.NewGreetServiceClient(gateway.Client(), gateway.URL),
		gatewayURL: gateway.URL,
		upstream:   upstream,
		records:    records,
	}
}

func destinationsTo(t *testing.T, rawURL string) registry.Destinations {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", rawURL, err)
	}

	destinations := make(registry.Destinations)
	for _, binding := range catalog.Bindings() {
		destinations[binding.Destination] = registry.Destination{URL: parsed}
	}

	return destinations
}

func gatewayError(t *testing.T, err error) *connectrpc.Error {
	t.Helper()

	if err == nil {
		t.Fatal("the call succeeded, want an error")
	}

	var got *connectrpc.Error
	if !errors.As(err, &got) {
		t.Fatalf("error = %v, want a *connect.Error", err)
	}

	return got
}

func TestGatewayForwardsAnonymousProcedures(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	res, err := fixture.client.Ping(t.Context(), connectrpc.NewRequest(&greetv1.PingRequest{}))
	if err != nil {
		t.Fatalf("Ping() error = %v, want nil", err)
	}

	if got, want := res.Msg.GetMessage(), "pong"; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}

	if got := len(fixture.records); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

func TestGatewayStopsAuthenticatedProceduresBeforeTheUpstream(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	_, err := fixture.client.Greet(t.Context(), connectrpc.NewRequest(&greetv1.GreetRequest{Name: "tolo"}))

	if got, want := gatewayError(t, err).Code(), connectrpc.CodeUnauthenticated; got != want {
		t.Errorf("code = %v, want %v", got, want)
	}

	if got := len(fixture.records); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}

func TestGatewayCarriesTheClientDeadlineToTheUpstream(t *testing.T) {
	t.Parallel()

	const timeout = 3 * time.Second

	fixture := newGateway(t)

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	if _, err := fixture.client.Ping(ctx, connectrpc.NewRequest(&greetv1.PingRequest{})); err != nil {
		t.Fatalf("Ping() error = %v, want nil", err)
	}

	remaining := <-fixture.records

	if remaining <= 0 || remaining > timeout {
		t.Errorf("the upstream deadline leaves %v, want more than 0 and at most %v", remaining, timeout)
	}
}

func TestGatewayAnswersAnUnreachableUpstreamWithUnavailable(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)
	fixture.upstream.Close()

	_, err := fixture.client.Ping(t.Context(), connectrpc.NewRequest(&greetv1.PingRequest{}))

	got := gatewayError(t, err)

	if got.Code() != connectrpc.CodeUnavailable {
		t.Errorf("code = %v, want %v", got.Code(), connectrpc.CodeUnavailable)
	}

	if got.Message() != "upstream unavailable" {
		t.Errorf("message = %q, want %q", got.Message(), "upstream unavailable")
	}
}

func TestGatewayAnswersUnregisteredProceduresWithUnimplemented(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fixture.gatewayURL+"/greet.v1.GreetService/Absent", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, http.StatusNotImplemented; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}

	if got := len(fixture.records); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}
