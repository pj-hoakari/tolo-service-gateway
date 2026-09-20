package authn

import (
	"errors"
	"log/slog"
	"net/http"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	workloadAuthorizationHeader   = "Workload-Authorization"
	serverlessAuthorizationHeader = "X-Serverless-Authorization"
	authorizationHeader           = "Authorization"
	dpopHeader                    = "DPoP"
)

const (
	reasonWorkloadAuthorization = "workload_authorization"
	reasonExternalAuthorization = "external_authorization"
	reasonAnonymousRejected     = "anonymous_rejected"
)

var errUnauthenticated = errors.New("unauthenticated")

func Middleware(reg *registry.Registry, next http.Handler, fallback http.Handler) http.Handler {
	errorWriter := connectrpc.NewErrorWriter()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !errorWriter.IsSupported(r) {
			fallback.ServeHTTP(w, r)

			return
		}

		entry, registered := reg.Lookup(r.URL.Path)
		if !registered {
			fallback.ServeHTTP(w, r)

			return
		}

		if reason, rejected := rejectionOf(r.Header, entry); rejected {
			reject(w, r, errorWriter, entry.Procedure, reason)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func rejectionOf(header http.Header, entry registry.Entry) (string, bool) {
	if present(header, workloadAuthorizationHeader) || present(header, serverlessAuthorizationHeader) {
		return reasonWorkloadAuthorization, true
	}

	if present(header, authorizationHeader) || present(header, dpopHeader) {
		return reasonExternalAuthorization, true
	}

	if !entry.Anonymous {
		return reasonAnonymousRejected, true
	}

	return "", false
}

func present(header http.Header, name string) bool {
	_, ok := header[http.CanonicalHeaderKey(name)]

	return ok
}

func reject(w http.ResponseWriter, r *http.Request, errorWriter *connectrpc.ErrorWriter, procedure, reason string) {
	slog.WarnContext(r.Context(), "rpc request rejected", "procedure", procedure, "reason", reason)

	err := errorWriter.Write(w, r, connectrpc.NewError(connectrpc.CodeUnauthenticated, errUnauthenticated))
	if err != nil {
		slog.ErrorContext(r.Context(), "rejection response write failed", "error", err)
	}
}
