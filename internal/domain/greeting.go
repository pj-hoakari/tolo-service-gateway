// Package domain contains immutable models for the greet context.
package domain

import (
	"errors"
	"fmt"
)

// ErrGreetingNameRequired reports that a greeting was requested without a
// name.
var ErrGreetingNameRequired = errors.New("name is required")

// Greeting is an immutable greeting model.
type Greeting struct {
	name string
}

// NewGreeting validates the greeted name and builds a Greeting.
func NewGreeting(name string) (Greeting, error) {
	if name == "" {
		return Greeting{}, ErrGreetingNameRequired
	}

	return Greeting{name: name}, nil
}

func (g Greeting) Name() string { return g.name }

// Message renders the greeting text presented to the caller.
func (g Greeting) Message() string { return fmt.Sprintf("Hello, %s!", g.name) }
