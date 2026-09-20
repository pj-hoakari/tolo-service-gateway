package httpapi

import (
	"maps"
	"net/http"
	"slices"

	"github.com/pj-hoakari/tolo-service-gateway/internal/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

func RPCRoutes(reg *registry.Registry, handlers map[string]http.Handler) Routes {
	fallback := FallbackHandler()

	return func(mux *http.ServeMux) {
		for _, path := range slices.Sorted(maps.Keys(handlers)) {
			mux.Handle(path, authn.Middleware(reg, handlers[path], fallback))
		}
	}
}
