package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	workloadAuthorizationHeader   = "Workload-Authorization"
	serverlessAuthorizationHeader = "X-Serverless-Authorization"
	authorizationHeader           = "Authorization"
	dpopHeader                    = "DPoP"
)

const bearerScheme = "bearer"

const (
	ReasonWorkloadAuthorization        = "workload_authorization"
	ReasonExternalAuthorization        = "external_authorization"
	ReasonAnonymousRejected            = "anonymous_rejected"
	ReasonDPoPUnsupported              = "dpop_unsupported"
	ReasonMalformedAuthorization       = "malformed_authorization"
	ReasonVerifierUnavailable          = "verifier_unavailable"
	ReasonInvalidToken                 = "invalid_token"
	ReasonSenderConstrainedUnsupported = "sender_constrained_unsupported"
	ReasonInternalOnly                 = "internal_only"
	ReasonTokenUseMismatch             = "token_use_mismatch" //nolint:gosec // an audit vocabulary word, not a credential
	ReasonMissingScope                 = "missing_scope"
	ReasonIntrospectionUnavailable     = "introspection_unavailable"
)

var ErrVerifierUnavailable = errors.New("authn: the external token verifier is unavailable")

type ExternalToken struct {
	Subject           string
	ClientID          string
	TokenUse          string
	Scope             string
	JTI               string
	TenantID          string
	EventID           string
	ExpiresAt         time.Time
	SenderConstrained bool
}

type ExternalVerifier interface {
	Verify(ctx context.Context, token string) (ExternalToken, error)
}

type Rejection struct {
	Code   connectrpc.Code
	Reason string
}

type Result struct {
	External *ExternalToken
}

type Authenticator struct {
	verifier ExternalVerifier
}

func NewAuthenticator(verifier ExternalVerifier) *Authenticator {
	return &Authenticator{verifier: verifier}
}

func (a *Authenticator) Authenticate(ctx context.Context, header http.Header, entry registry.Entry) (Result, *Rejection) {
	if present(header, workloadAuthorizationHeader) || present(header, serverlessAuthorizationHeader) {
		return anonymousResult(), unauthenticated(ReasonWorkloadAuthorization)
	}

	if present(header, dpopHeader) {
		return anonymousResult(), unauthenticated(ReasonDPoPUnsupported)
	}

	values, carried := header[http.CanonicalHeaderKey(authorizationHeader)]
	if !carried {
		return withoutCredentials(entry)
	}

	return a.external(ctx, values, entry)
}

func (a *Authenticator) external(ctx context.Context, values []string, entry registry.Entry) (Result, *Rejection) {
	token, wellFormed := bearerToken(values)
	if !wellFormed {
		return anonymousResult(), unauthenticated(ReasonMalformedAuthorization)
	}

	if a.verifier == nil {
		return anonymousResult(), unauthenticated(ReasonExternalAuthorization)
	}

	verified, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return anonymousResult(), verificationRejection(ctx, err)
	}

	if verified.SenderConstrained {
		return anonymousResult(), unauthenticated(ReasonSenderConstrainedUnsupported)
	}

	return Result{External: &verified}, authorize(verified, entry)
}

func verificationRejection(ctx context.Context, err error) *Rejection {
	slog.WarnContext(ctx, "external token verification failed", "error", err)

	if errors.Is(err, ErrVerifierUnavailable) {
		return &Rejection{Code: connectrpc.CodeUnavailable, Reason: ReasonVerifierUnavailable}
	}

	return unauthenticated(ReasonInvalidToken)
}

func authorize(token ExternalToken, entry registry.Entry) *Rejection {
	if len(entry.ExternalTokenUses) == 0 {
		if entry.Service {
			return &Rejection{Code: connectrpc.CodePermissionDenied, Reason: ReasonInternalOnly}
		}

		return unauthenticated(ReasonTokenUseMismatch)
	}

	if !slices.Contains(entry.ExternalTokenUses, token.TokenUse) {
		return unauthenticated(ReasonTokenUseMismatch)
	}

	granted := strings.Fields(token.Scope)

	for _, required := range entry.RequiredScopes {
		if !slices.Contains(granted, required) {
			return &Rejection{Code: connectrpc.CodePermissionDenied, Reason: ReasonMissingScope}
		}
	}

	if entry.Introspection {
		return unauthenticated(ReasonIntrospectionUnavailable)
	}

	return nil
}

func withoutCredentials(entry registry.Entry) (Result, *Rejection) {
	if !entry.Anonymous {
		return anonymousResult(), unauthenticated(ReasonAnonymousRejected)
	}

	return anonymousResult(), nil
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}

	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], bearerScheme) {
		return "", false
	}

	return fields[1], true
}

func anonymousResult() Result {
	return Result{External: nil}
}

func unauthenticated(reason string) *Rejection {
	return &Rejection{Code: connectrpc.CodeUnauthenticated, Reason: reason}
}

func present(header http.Header, name string) bool {
	_, ok := header[http.CanonicalHeaderKey(name)]

	return ok
}
