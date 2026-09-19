package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pj-hoakari/go-service-template/internal/application"
	"github.com/pj-hoakari/go-service-template/internal/domain"
)

func TestGreet(t *testing.T) {
	t.Parallel()

	service := application.NewGreetService()

	greeting, err := service.Greet(context.Background(), application.GreetInput{Name: "Ada"})
	if err != nil {
		t.Fatalf("Greet() error = %v", err)
	}

	if got, want := greeting.Message(), "Hello, Ada!"; got != want {
		t.Errorf("Message() = %q, want %q", got, want)
	}
}

func TestGreetValidatesInput(t *testing.T) {
	t.Parallel()

	service := application.NewGreetService()

	_, err := service.Greet(context.Background(), application.GreetInput{})
	if !errors.Is(err, domain.ErrGreetingNameRequired) {
		t.Errorf("Greet() error = %v, want %v", err, domain.ErrGreetingNameRequired)
	}
}
