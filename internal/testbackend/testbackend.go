package testbackend

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	connectrpc "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/pj-hoakari/internal-jwt-handling/interceptor"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
)

const messageGreetingNameRequired = "name is required"

func NewHandler(tokenVerifier interceptor.TokenVerifier) (http.Handler, error) {
	auth, err := interceptor.New(
		tokenVerifier,
		greetv1connect.GreetServicePolicies,
		interceptor.WithErrorReporter(reportAuthRejection),
	)
	if err != nil {
		return nil, fmt.Errorf("create GreetService authentication interceptor: %w", err)
	}

	server := connectrpc.NewServer(auth)
	greetv1connect.RegisterGreetServiceHandler(server, greetService{UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{}})

	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)

	return mux, nil
}

func reportAuthRejection(ctx context.Context, procedure string, err error) {
	slog.WarnContext(ctx, "internal JWT rejected", "procedure", procedure, "error", err)
}

type greetService struct {
	greetv1connect.UnimplementedGreetServiceHandler
}

func (greetService) Greet(_ context.Context, req *greetv1.GreetRequest) (*greetv1.GreetResponse, error) {
	name := req.GetName()
	if name == "" {
		return nil, connectrpc.NewError(connectrpc.CodeInvalidArgument, messageGreetingNameRequired)
	}

	return &greetv1.GreetResponse{
		Greeting: fmt.Sprintf("Hello, %s!", name),
	}, nil
}

func (greetService) Ping(_ context.Context, _ *greetv1.PingRequest) (*greetv1.PingResponse, error) {
	return &greetv1.PingResponse{
		Message: "pong",
	}, nil
}
