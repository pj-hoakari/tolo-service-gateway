package authn

import (
	"net/http"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	workloadAuthorizationHeader   = "Workload-Authorization"
	serverlessAuthorizationHeader = "X-Serverless-Authorization"
	authorizationHeader           = "Authorization"
	dpopHeader                    = "DPoP"
)

const (
	ReasonWorkloadAuthorization = "workload_authorization"
	ReasonExternalAuthorization = "external_authorization"
	ReasonAnonymousRejected     = "anonymous_rejected"
)

func Reject(header http.Header, entry registry.Entry) (string, bool) {
	if present(header, workloadAuthorizationHeader) || present(header, serverlessAuthorizationHeader) {
		return ReasonWorkloadAuthorization, true
	}

	if present(header, authorizationHeader) || present(header, dpopHeader) {
		return ReasonExternalAuthorization, true
	}

	if !entry.Anonymous {
		return ReasonAnonymousRejected, true
	}

	return "", false
}

func present(header http.Header, name string) bool {
	_, ok := header[http.CanonicalHeaderKey(name)]

	return ok
}
