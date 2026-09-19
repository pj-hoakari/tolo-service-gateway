// Package application contains use cases for the greet context.
package application

import (
	"context"

	"github.com/pj-hoakari/go-service-template/internal/domain"
)

// GreetInput contains the values accepted by the Greet use case.
type GreetInput struct {
	Name string
}

// GreetUseCase builds a greeting for the named caller.
type GreetUseCase interface {
	Greet(context.Context, GreetInput) (domain.Greeting, error)
}

// GreetUseCases groups the greet operations exposed by the Connect transport.
type GreetUseCases interface {
	GreetUseCase
}

// GreetService implements greet use cases.
type GreetService struct{}

func NewGreetService() *GreetService {
	return &GreetService{}
}

func (s *GreetService) Greet(_ context.Context, input GreetInput) (domain.Greeting, error) {
	return domain.NewGreeting(input.Name)
}
