package catalog

import (
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const testBackendDestination = "tolo-testbackend"

func Bindings() []registry.Binding {
	return []registry.Binding{
		{
			Service:     greetv1connect.GreetServiceName,
			Destination: testBackendDestination,
			Policies:    greetv1connect.GreetServicePolicies,
		},
	}
}

func Overrides() registry.Overrides {
	return registry.Overrides{
		Introspection: nil,
	}
}
