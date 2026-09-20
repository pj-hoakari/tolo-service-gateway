package authn_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	anonymousProcedure     = "/greet.v1.GreetService/Ping"
	authenticatedProcedure = "/greet.v1.GreetService/Greet"
	serviceOnlyProcedure   = "/tolo.tenant.v1.TenantService/GetEvent"
)

const (
	acceptedToken    = "external-token-a"
	constrainedToken = "external-token-b"
	otherUseToken    = "external-token-c"
	scopelessToken   = "external-token-d"
	unknownToken     = "external-token-e"
)

const (
	tenantID = "a1b2c3d4e5f60718"
	subject  = "user-1"
	clientID = "admin-ui"
	sourceID = "external-jti-1"
)

var errUnknownToken = errors.New("unknown token")

type fakeVerifier struct {
	tokens map[string]authn.ExternalToken
	err    error
}

func (v fakeVerifier) Verify(_ context.Context, token string) (authn.ExternalToken, error) {
	var zero authn.ExternalToken

	if v.err != nil {
		return zero, v.err
	}

	verified, known := v.tokens[token]
	if !known {
		return zero, fmt.Errorf("%w: %d bytes", errUnknownToken, len(token))
	}

	return verified, nil
}

func externalToken(tokenUse, scope string) authn.ExternalToken {
	return authn.ExternalToken{
		Subject:           subject,
		ClientID:          clientID,
		TokenUse:          tokenUse,
		Scope:             scope,
		JTI:               sourceID,
		TenantID:          tenantID,
		EventID:           "",
		ExpiresAt:         time.Now().Add(15 * time.Minute),
		SenderConstrained: false,
	}
}

func newAuthenticator() *authn.Authenticator {
	constrained := externalToken("tenant_access", "greeting.read")
	constrained.SenderConstrained = true

	return authn.NewAuthenticator(fakeVerifier{
		tokens: map[string]authn.ExternalToken{
			acceptedToken:    externalToken("tenant_access", "greeting.read"),
			constrainedToken: constrained,
			otherUseToken:    externalToken("registration", "greeting.read"),
			scopelessToken:   externalToken("tenant_access", ""),
		},
		err: nil,
	})
}

func lookup(t *testing.T, procedure string) registry.Entry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	entry, registered := built.Lookup(procedure)
	if !registered {
		t.Fatalf("Lookup(%q) is not registered", procedure)
	}

	return entry
}

func headerWith(values map[string][]string) http.Header {
	header := make(http.Header)

	for name, value := range values {
		header[http.CanonicalHeaderKey(name)] = value
	}

	return header
}

func bearer(token string) map[string][]string {
	return map[string][]string{"Authorization": {"Bearer " + token}}
}

func TestAuthenticateAcceptsAnAnonymousProcedureWithoutCredentials(t *testing.T) {
	t.Parallel()

	result, rejection := newAuthenticator().Authenticate(t.Context(), headerWith(nil), lookup(t, anonymousProcedure))

	if rejection != nil {
		t.Fatalf("Authenticate() rejected the request with %q, want it accepted", rejection.Reason)
	}

	if result.External != nil {
		t.Errorf("result.External = %#v, want nil", result.External)
	}
}

func TestAuthenticateAcceptsAVerifiedExternalToken(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string][]string{
		"the bearer scheme":              bearer(acceptedToken),
		"the bearer scheme in lowercase": {"Authorization": {"bearer " + acceptedToken}},
		"the bearer scheme in uppercase": {"Authorization": {"BEARER " + acceptedToken}},
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, rejection := newAuthenticator().Authenticate(
				t.Context(),
				headerWith(header),
				lookup(t, authenticatedProcedure),
			)

			if rejection != nil {
				t.Fatalf("Authenticate() rejected the request with %q, want it accepted", rejection.Reason)
			}

			if result.External == nil {
				t.Fatal("result.External = nil, want the verified token")
			}

			if got, want := result.External.Subject, subject; got != want {
				t.Errorf("subject = %q, want %q", got, want)
			}

			if got, want := result.External.JTI, sourceID; got != want {
				t.Errorf("jti = %q, want %q", got, want)
			}
		})
	}
}

func TestAuthenticateNamesTheReason(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		procedure  string
		header     map[string][]string
		wantCode   connectrpc.Code
		wantReason string
	}{
		"a workload credential": {
			procedure:  anonymousProcedure,
			header:     map[string][]string{"Workload-Authorization": {""}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonWorkloadAuthorization,
		},
		"a serverless credential": {
			procedure:  anonymousProcedure,
			header:     map[string][]string{"X-Serverless-Authorization": {"Bearer inside"}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonWorkloadAuthorization,
		},
		"a workload credential is named before an external token": {
			procedure: authenticatedProcedure,
			header: map[string][]string{
				"Workload-Authorization": {"Bearer inside"},
				"Authorization":          {"Bearer " + acceptedToken},
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonWorkloadAuthorization,
		},
		"a DPoP proof on its own": {
			procedure:  anonymousProcedure,
			header:     map[string][]string{"DPoP": {"proof"}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonDPoPUnsupported,
		},
		"a DPoP proof beside a usable token": {
			procedure: authenticatedProcedure,
			header: map[string][]string{
				"DPoP":          {"proof"},
				"Authorization": {"Bearer " + acceptedToken},
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonDPoPUnsupported,
		},
		"two authorization values": {
			procedure: authenticatedProcedure,
			header: map[string][]string{
				"Authorization": {"Bearer " + acceptedToken, "Bearer " + otherUseToken},
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonMalformedAuthorization,
		},
		"a scheme without a token": {
			procedure:  authenticatedProcedure,
			header:     map[string][]string{"Authorization": {"Bearer"}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonMalformedAuthorization,
		},
		"an empty authorization value": {
			procedure:  authenticatedProcedure,
			header:     map[string][]string{"Authorization": {""}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonMalformedAuthorization,
		},
		"another scheme": {
			procedure:  authenticatedProcedure,
			header:     map[string][]string{"Authorization": {"Basic " + acceptedToken}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonMalformedAuthorization,
		},
		"a token without a scheme": {
			procedure:  authenticatedProcedure,
			header:     map[string][]string{"Authorization": {acceptedToken}},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonMalformedAuthorization,
		},
		"a token the verifier does not know": {
			procedure:  authenticatedProcedure,
			header:     bearer(unknownToken),
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonInvalidToken,
		},
		"a sender-constrained token": {
			procedure:  authenticatedProcedure,
			header:     bearer(constrainedToken),
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonSenderConstrainedUnsupported,
		},
		"an external token on a service-only procedure": {
			procedure:  serviceOnlyProcedure,
			header:     bearer(acceptedToken),
			wantCode:   connectrpc.CodePermissionDenied,
			wantReason: authn.ReasonInternalOnly,
		},
		"an external token on an anonymous procedure": {
			procedure:  anonymousProcedure,
			header:     bearer(acceptedToken),
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonTokenUseMismatch,
		},
		"a token use the procedure does not accept": {
			procedure:  authenticatedProcedure,
			header:     bearer(otherUseToken),
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonTokenUseMismatch,
		},
		"a token without the required scope": {
			procedure:  authenticatedProcedure,
			header:     bearer(scopelessToken),
			wantCode:   connectrpc.CodePermissionDenied,
			wantReason: authn.ReasonMissingScope,
		},
		"an authenticated procedure without credentials": {
			procedure:  authenticatedProcedure,
			header:     nil,
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonAnonymousRejected,
		},
		"a service-only procedure without credentials": {
			procedure:  serviceOnlyProcedure,
			header:     nil,
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonAnonymousRejected,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, rejection := newAuthenticator().Authenticate(t.Context(), headerWith(test.header), lookup(t, test.procedure))

			if rejection == nil {
				t.Fatal("Authenticate() accepted the request, want it rejected")
			}

			if rejection.Code != test.wantCode {
				t.Errorf("code = %v, want %v", rejection.Code, test.wantCode)
			}

			if rejection.Reason != test.wantReason {
				t.Errorf("reason = %q, want %q", rejection.Reason, test.wantReason)
			}
		})
	}
}

func TestAuthenticateKeepsTheVerifiedTokenOnAnAuthorizationFailure(t *testing.T) {
	t.Parallel()

	result, rejection := newAuthenticator().Authenticate(
		t.Context(),
		headerWith(bearer(scopelessToken)),
		lookup(t, authenticatedProcedure),
	)

	if rejection == nil {
		t.Fatal("Authenticate() accepted the request, want it rejected")
	}

	if result.External == nil {
		t.Fatal("result.External = nil, want the verified token")
	}

	if got, want := result.External.ClientID, clientID; got != want {
		t.Errorf("client ID = %q, want %q", got, want)
	}
}

func TestAuthenticateLeavesTheTokenOutOfTheResultBeforeItIsVerified(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string][]string{
		"a malformed authorization":          {"Authorization": {"Bearer"}},
		"a token the verifier does not know": bearer(unknownToken),
		"a sender-constrained token":         bearer(constrainedToken),
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, rejection := newAuthenticator().Authenticate(
				t.Context(),
				headerWith(header),
				lookup(t, authenticatedProcedure),
			)

			if rejection == nil {
				t.Fatal("Authenticate() accepted the request, want it rejected")
			}

			if result.External != nil {
				t.Errorf("result.External = %#v, want nil", result.External)
			}
		})
	}
}

func TestAuthenticateRejectsExternalTokensWithoutAVerifier(t *testing.T) {
	t.Parallel()

	for name, procedure := range map[string]string{
		"an anonymous procedure":     anonymousProcedure,
		"an authenticated procedure": authenticatedProcedure,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, rejection := authn.NewAuthenticator(nil).Authenticate(
				t.Context(),
				headerWith(bearer(acceptedToken)),
				lookup(t, procedure),
			)

			if rejection == nil {
				t.Fatal("Authenticate() accepted the request, want it rejected")
			}

			if rejection.Code != connectrpc.CodeUnauthenticated {
				t.Errorf("code = %v, want %v", rejection.Code, connectrpc.CodeUnauthenticated)
			}

			if rejection.Reason != authn.ReasonExternalAuthorization {
				t.Errorf("reason = %q, want %q", rejection.Reason, authn.ReasonExternalAuthorization)
			}
		})
	}
}

func TestAuthenticateReportsAnUnavailableVerifier(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err        error
		wantCode   connectrpc.Code
		wantReason string
	}{
		"the verifier cannot be reached": {
			err:        fmt.Errorf("fetch the JWKS: %w", authn.ErrVerifierUnavailable),
			wantCode:   connectrpc.CodeUnavailable,
			wantReason: authn.ReasonVerifierUnavailable,
		},
		"the token does not verify": {
			err:        errors.New("the signature does not match"),
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: authn.ReasonInvalidToken,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			authenticator := authn.NewAuthenticator(fakeVerifier{tokens: nil, err: test.err})

			_, rejection := authenticator.Authenticate(
				t.Context(),
				headerWith(bearer(acceptedToken)),
				lookup(t, authenticatedProcedure),
			)

			if rejection == nil {
				t.Fatal("Authenticate() accepted the request, want it rejected")
			}

			if rejection.Code != test.wantCode {
				t.Errorf("code = %v, want %v", rejection.Code, test.wantCode)
			}

			if rejection.Reason != test.wantReason {
				t.Errorf("reason = %q, want %q", rejection.Reason, test.wantReason)
			}
		})
	}
}

func TestAuthenticateMatchesScopesWhole(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		required []string
		scope    string
		accepted bool
	}{
		"every required scope is granted": {
			required: []string{"events.read", "events.manage"},
			scope:    "events.read events.manage tenant.read",
			accepted: true,
		},
		"one of the required scopes is missing": {
			required: []string{"events.read", "events.manage"},
			scope:    "events.read tenant.read",
			accepted: false,
		},
		"a longer scope does not stand in for the required one": {
			required: []string{"events.read"},
			scope:    "events.readx",
			accepted: false,
		},
		"a procedure without required scopes takes any token": {
			required: nil,
			scope:    "",
			accepted: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			entry := registry.Entry{
				Procedure:         "/tolo.tenant.v1.TenantService/ListEvents",
				Destination:       "tolo-tenant-management",
				Anonymous:         false,
				ExternalTokenUses: []string{"tenant_access"},
				Service:           false,
				RequiredScopes:    test.required,
				Introspection:     false,
			}

			authenticator := authn.NewAuthenticator(fakeVerifier{
				tokens: map[string]authn.ExternalToken{
					acceptedToken: externalToken("tenant_access", test.scope),
				},
				err: nil,
			})

			_, rejection := authenticator.Authenticate(t.Context(), headerWith(bearer(acceptedToken)), entry)

			if test.accepted {
				if rejection != nil {
					t.Fatalf("Authenticate() rejected the request with %q, want it accepted", rejection.Reason)
				}

				return
			}

			if rejection == nil {
				t.Fatal("Authenticate() accepted the request, want it rejected")
			}

			if rejection.Code != connectrpc.CodePermissionDenied {
				t.Errorf("code = %v, want %v", rejection.Code, connectrpc.CodePermissionDenied)
			}

			if rejection.Reason != authn.ReasonMissingScope {
				t.Errorf("reason = %q, want %q", rejection.Reason, authn.ReasonMissingScope)
			}
		})
	}
}
