package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	connectrpc "connectrpc.com/connect"
)

var errUnimplementedProcedure = errors.New("unimplemented")

func FallbackRoutes() Routes {
	errorWriter := connectrpc.NewErrorWriter()

	return func(mux *http.ServeMux) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			handleFallback(w, r, errorWriter)
		})
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
