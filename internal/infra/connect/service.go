package connect

import (
	"context"
	"errors"
	"log/slog"

	connectrpc "connectrpc.com/connect"

	greetv1 "github.com/pj-hoakari/go-service-template/gen/greet/v1"
	"github.com/pj-hoakari/go-service-template/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/go-service-template/internal/application"
	"github.com/pj-hoakari/go-service-template/internal/domain"
)

// errInternal is the only detail a client learns about an internal failure.
var errInternal = errors.New("internal error")

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

// Service is the Connect transport implementation of GreetService.
type Service struct {
	greetv1connect.UnimplementedGreetServiceHandler
	greetService application.GreetUseCases
}

func NewService(greetService application.GreetUseCases) *Service {
	return &Service{
		UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{},
		greetService:                     greetService,
	}
}

func (s *Service) Greet(ctx context.Context, req *connectrpc.Request[greetv1.GreetRequest]) (*connectrpc.Response[greetv1.GreetResponse], error) {
	greeting, err := s.greetService.Greet(ctx, application.GreetInput{
		Name: req.Msg.GetName(),
	})
	if err != nil {
		if errors.Is(err, domain.ErrGreetingNameRequired) {
			return nil, connectrpc.NewError(connectrpc.CodeInvalidArgument, err)
		}

		return nil, InternalError(ctx, err)
	}

	return connectrpc.NewResponse(&greetv1.GreetResponse{
		Greeting: greeting.Message(),
	}), nil
}
