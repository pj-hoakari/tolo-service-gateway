package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	connectrpc "connectrpc.com/connect"
)

var errUnimplementedProcedure = errors.New("unimplemented")

func FallbackHandler() http.Handler {
	errorWriter := connectrpc.NewErrorWriter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleFallback(w, r, errorWriter)
	})
}

func FallbackRoutes() Routes {
	handler := FallbackHandler()

	return func(mux *http.ServeMux) {
		mux.Handle("/", handler)
	}
}

func handleFallback(w http.ResponseWriter, r *http.Request, errorWriter *connectrpc.ErrorWriter) {
	if r.Method != http.MethodPost || !errorWriter.IsSupported(r) {
		http.NotFound(w, r)

		return
	}

	err := errorWriter.Write(w, r, connectrpc.NewError(connectrpc.CodeUnimplemented, errUnimplementedProcedure))
	if err != nil {
		slog.ErrorContext(r.Context(), "fallback response write failed", "error", err)
	}
}
