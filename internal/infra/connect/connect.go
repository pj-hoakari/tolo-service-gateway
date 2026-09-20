package connect

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

var errUnimplementedProcedure = errors.New("unimplemented")

func Routes(reg *registry.Registry, handlers map[string]http.Handler) func(mux *http.ServeMux) {
	unimplemented := newUnimplementedHandler()

	return func(mux *http.ServeMux) {
		for _, path := range slices.Sorted(maps.Keys(handlers)) {
			mux.Handle(path, authn.Middleware(reg, handlers[path], unimplemented))
		}

		mux.Handle("/", unimplemented)
	}
}

func newUnimplementedHandler() http.Handler {
	errorWriter := connectrpc.NewErrorWriter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleUnimplemented(w, r, errorWriter)
	})
}

func handleUnimplemented(w http.ResponseWriter, r *http.Request, errorWriter *connectrpc.ErrorWriter) {
	if r.Method != http.MethodPost || !errorWriter.IsSupported(r) {
		http.NotFound(w, r)

		return
	}

	err := errorWriter.Write(w, r, connectrpc.NewError(connectrpc.CodeUnimplemented, errUnimplementedProcedure))
	if err != nil {
		slog.ErrorContext(r.Context(), "fallback response write failed", "error", err)
	}
}
