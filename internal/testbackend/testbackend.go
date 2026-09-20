package testbackend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/internal-jwt-handling/interceptor"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
)

var errGreetingNameRequired = errors.New("name is required")

func NewHandler(tokenVerifier interceptor.TokenVerifier) (http.Handler, error) {
	auth, err := interceptor.New(
		tokenVerifier,
		greetv1connect.GreetServicePolicies,
		interceptor.WithErrorReporter(reportAuthRejection),
	)
	if err != nil {
		return nil, fmt.Errorf("create GreetService authentication interceptor: %w", err)
	}

	mux := http.NewServeMux()

	path, handler := greetv1connect.NewGreetServiceHandler(
		greetService{UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{}},
		connectrpc.WithInterceptors(auth),
	)
	mux.Handle(path, handler)

	return mux, nil
}

func reportAuthRejection(ctx context.Context, procedure string, err error) {
	slog.WarnContext(ctx, "internal JWT rejected", "procedure", procedure, "error", err)
}

type greetService struct {
	greetv1connect.UnimplementedGreetServiceHandler
}

func (greetService) Greet(_ context.Context, req *connectrpc.Request[greetv1.GreetRequest]) (*connectrpc.Response[greetv1.GreetResponse], error) {
	name := req.Msg.GetName()
	if name == "" {
		return nil, connectrpc.NewError(connectrpc.CodeInvalidArgument, errGreetingNameRequired)
	}

	return connectrpc.NewResponse(&greetv1.GreetResponse{
		Greeting: fmt.Sprintf("Hello, %s!", name),
	}), nil
}

func (greetService) Ping(_ context.Context, _ *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
	return connectrpc.NewResponse(&greetv1.PingResponse{
		Message: "pong",
	}), nil
}
