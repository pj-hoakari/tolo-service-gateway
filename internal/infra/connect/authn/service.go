package authn

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ReasonAmbiguousServiceCredential = "ambiguous_service_credential"
	ReasonMissingServiceCredential   = "missing_service_credential"
	ReasonMalformedCallerService     = "malformed_caller_service"
	ReasonInvalidContext             = "invalid_context"
)

type ServiceCredential struct {
	Caller       string
	ContextToken string
}

func ServiceCall(header http.Header) (ServiceCredential, *Rejection) {
	var zero ServiceCredential

	if present(header, dpopHeader) {
		return zero, unauthenticated(ReasonDPoPUnsupported)
	}

	authorization, carriesContext := header[http.CanonicalHeaderKey(authorizationHeader)]
	callers, declaresCaller := header[http.CanonicalHeaderKey(callerServiceHeader)]

	switch {
	case carriesContext && declaresCaller:
		return zero, unauthenticated(ReasonAmbiguousServiceCredential)
	case declaresCaller:
		if len(callers) != 1 || callers[0] == "" {
			return zero, unauthenticated(ReasonMalformedCallerService)
		}

		return ServiceCredential{Caller: callers[0], ContextToken: ""}, nil
	case carriesContext:
		token, wellFormed := bearerToken(authorization)
		if !wellFormed {
			return zero, unauthenticated(ReasonMalformedAuthorization)
		}

		audience, ok := singleAudience(token)
		if !ok {
			return zero, unauthenticated(ReasonInvalidContext)
		}

		return ServiceCredential{Caller: audience, ContextToken: token}, nil
	default:
		return zero, unauthenticated(ReasonMissingServiceCredential)
	}
}

func singleAudience(token string) (string, bool) {
	var claims jwt.RegisteredClaims

	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return "", false
	}

	if len(claims.Audience) != 1 || claims.Audience[0] == "" {
		return "", false
	}

	return claims.Audience[0], true
}
