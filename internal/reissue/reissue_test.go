package reissue_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
	"github.com/pj-hoakari/tolo-service-gateway/internal/reissue"
	"github.com/pj-hoakari/tolo-service-gateway/internal/token"
)

const (
	gatewayIssuerID = "service-gateway"
	signingKeyID    = "local-key-1"

	getEventProcedure               = "/tolo.tenant.v1.TenantService/GetEvent"
	getObservationSettingsProcedure = "/tolo.tenant.v1.TenantService/GetObservationSettings"

	graphAuthoring   = "tolo-graph-authoring"
	observation      = "tolo-observation"
	guestService     = "tolo-guest-service"
	tenantManagement = "tolo-tenant-management"

	userSubject    = "user-1"
	clientID       = "admin-ui"
	externalJTI    = "external-jti-1"
	grantedScope   = "events.read"
	tenantPublicID = "0123456789abcdef"
	eventPublicID  = "fedcba9876543210"
)

type staticKeyProvider struct {
	keySet issuer.KeySet
}

func (p staticKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	return p.keySet, nil
}

func newKeys(t *testing.T) issuer.KeyProvider {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	return staticKeyProvider{
		keySet: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: signingKeyID, Key: key},
			Published: nil,
		},
	}
}

func newIssuer(t *testing.T, keys issuer.KeyProvider, opts ...issuer.Option) *issuer.Issuer {
	t.Helper()

	internalIssuer, err := issuer.New(gatewayIssuerID, keys, opts...)
	if err != nil {
		t.Fatalf("issuer.New() error = %v, want nil", err)
	}

	return internalIssuer
}

func newRegistry(t *testing.T) *registry.Registry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("registry.Build() error = %v, want nil", err)
	}

	return built
}

func newReissuer(t *testing.T, keys issuer.KeyProvider, tokens reissue.ServiceIssuer, edges []edgepolicy.Edge) *reissue.Reissuer {
	t.Helper()

	policy, err := edgepolicy.Build(edges, newRegistry(t))
	if err != nil {
		t.Fatalf("edgepolicy.Build() error = %v, want nil", err)
	}

	contexts, err := token.NewContextVerifier(gatewayIssuerID, keys)
	if err != nil {
		t.Fatalf("NewContextVerifier() error = %v, want nil", err)
	}

	reissuer, err := reissue.New(newRegistry(t), policy, contexts, tokens)
	if err != nil {
		t.Fatalf("reissue.New() error = %v, want nil", err)
	}

	return reissuer
}

func edge(caller, procedure string, tokenUses []string, machineChain, newMachineOrigin bool) edgepolicy.Edge {
	return edgepolicy.Edge{
		Caller:              caller,
		Procedure:           procedure,
		UserOriginTokenUses: tokenUses,
		MachineChain:        machineChain,
		NewMachineOrigin:    newMachineOrigin,
	}
}

func eventAccessContext(t *testing.T, internalIssuer *issuer.Issuer, audience string) issuer.Issued {
	t.Helper()

	issued, err := internalIssuer.IssueFromExternal(t.Context(), issuer.ExternalTokenInput{
		Audience:        audience,
		TokenUse:        internaljwt.TokenUseEventAccess,
		Subject:         userSubject,
		ClientID:        clientID,
		Scope:           grantedScope,
		SourceJTI:       externalJTI,
		SourceExpiresAt: time.Now().Add(15 * time.Minute),
		TenantPublicID:  tenantPublicID,
		EventPublicID:   eventPublicID,
	})
	if err != nil {
		t.Fatalf("IssueFromExternal() error = %v, want nil", err)
	}

	return issued
}

func tenantAccessContext(t *testing.T, internalIssuer *issuer.Issuer, audience string) issuer.Issued {
	t.Helper()

	issued, err := internalIssuer.IssueFromExternal(t.Context(), issuer.ExternalTokenInput{
		Audience:        audience,
		TokenUse:        internaljwt.TokenUseTenantAccess,
		Subject:         userSubject,
		ClientID:        clientID,
		Scope:           grantedScope,
		SourceJTI:       externalJTI,
		SourceExpiresAt: time.Now().Add(15 * time.Minute),
		TenantPublicID:  tenantPublicID,
		EventPublicID:   "",
	})
	if err != nil {
		t.Fatalf("IssueFromExternal() error = %v, want nil", err)
	}

	return issued
}

func userOriginServiceContext(t *testing.T, internalIssuer *issuer.Issuer, audience, caller string) issuer.Issued {
	t.Helper()

	first := eventAccessContext(t, internalIssuer, caller)

	issued, err := internalIssuer.IssueUserOriginService(t.Context(), issuer.UserOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       first.Claims,
	})
	if err != nil {
		t.Fatalf("IssueUserOriginService() error = %v, want nil", err)
	}

	return issued
}

func machineOriginContext(t *testing.T, internalIssuer *issuer.Issuer, audience, caller string) issuer.Issued {
	t.Helper()

	issued, err := internalIssuer.IssueMachineOriginService(t.Context(), issuer.MachineOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       nil,
	})
	if err != nil {
		t.Fatalf("IssueMachineOriginService() error = %v, want nil", err)
	}

	return issued
}

func TestReissueRewritesAUserOriginContextForTheNextHop(t *testing.T) {
	t.Parallel()

	keys := newKeys(t)
	internalIssuer := newIssuer(t, keys)
	edges := []edgepolicy.Edge{
		edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false),
	}
	contextToken := eventAccessContext(t, internalIssuer, graphAuthoring)

	result, err := newReissuer(t, keys, internalIssuer, edges).Reissue(t.Context(), reissue.Request{
		Caller:       graphAuthoring,
		Procedure:    getEventProcedure,
		ContextToken: contextToken.Token,
	})
	if err != nil {
		t.Fatalf("Reissue() error = %v, want nil", err)
	}

	if result.Origin != reissue.OriginUser {
		t.Errorf("Origin = %q, want %q", result.Origin, reissue.OriginUser)
	}

	if result.Edge.Procedure != getEventProcedure {
		t.Errorf("Edge.Procedure = %q, want %q", result.Edge.Procedure, getEventProcedure)
	}

	claims := result.Issued.Claims

	if claims.TokenUse != internaljwt.TokenUseService {
		t.Errorf("token_use = %q, want %q", claims.TokenUse, internaljwt.TokenUseService)
	}

	if len(claims.Audience) != 1 || claims.Audience[0] != tenantManagement {
		t.Errorf("aud = %v, want [%q]", claims.Audience, tenantManagement)
	}

	if claims.Subject != graphAuthoring || claims.ClientID != graphAuthoring {
		t.Errorf("sub = %q, client_id = %q, want %q for both", claims.Subject, claims.ClientID, graphAuthoring)
	}

	if claims.OriginSub != userSubject {
		t.Errorf("origin_sub = %q, want %q", claims.OriginSub, userSubject)
	}

	if claims.Scope != contextToken.Claims.Scope {
		t.Errorf("scope = %q, want %q", claims.Scope, contextToken.Claims.Scope)
	}

	if claims.Txn != contextToken.Claims.Txn {
		t.Errorf("txn = %q, want %q", claims.Txn, contextToken.Claims.Txn)
	}

	if claims.TenantPublicID != tenantPublicID || claims.EventPublicID != eventPublicID {
		t.Errorf("tenant_id = %q, event_id = %q, want %q and %q", claims.TenantPublicID, claims.EventPublicID, tenantPublicID, eventPublicID)
	}

	if claims.SourceJTI != contextToken.Claims.ID {
		t.Errorf("src_jti = %q, want %q", claims.SourceJTI, contextToken.Claims.ID)
	}

	if claims.ID == "" || claims.ID == contextToken.Claims.ID {
		t.Errorf("jti = %q, want a new one next to %q", claims.ID, contextToken.Claims.ID)
	}
}

func TestReissueCarriesTheOriginSubjectOverASecondHop(t *testing.T) {
	t.Parallel()

	keys := newKeys(t)
	internalIssuer := newIssuer(t, keys)
	edges := []edgepolicy.Edge{
		edge(observation, getObservationSettingsProcedure, []string{internaljwt.TokenUseService}, false, false),
	}
	contextToken := userOriginServiceContext(t, internalIssuer, observation, guestService)

	result, err := newReissuer(t, keys, internalIssuer, edges).Reissue(t.Context(), reissue.Request{
		Caller:       observation,
		Procedure:    getObservationSettingsProcedure,
		ContextToken: contextToken.Token,
	})
	if err != nil {
		t.Fatalf("Reissue() error = %v, want nil", err)
	}

	if result.Origin != reissue.OriginUser {
		t.Errorf("Origin = %q, want %q", result.Origin, reissue.OriginUser)
	}

	claims := result.Issued.Claims

	if claims.OriginSub != userSubject {
		t.Errorf("origin_sub = %q, want %q", claims.OriginSub, userSubject)
	}

	if claims.Subject != observation {
		t.Errorf("sub = %q, want %q", claims.Subject, observation)
	}

	if claims.SourceJTI != contextToken.Claims.ID {
		t.Errorf("src_jti = %q, want %q", claims.SourceJTI, contextToken.Claims.ID)
	}

	if claims.Txn != contextToken.Claims.Txn {
		t.Errorf("txn = %q, want %q", claims.Txn, contextToken.Claims.Txn)
	}
}

func TestReissueKeepsOnlyTheChainOfAMachineOriginContext(t *testing.T) {
	t.Parallel()

	keys := newKeys(t)
	internalIssuer := newIssuer(t, keys)
	edges := []edgepolicy.Edge{
		edge(observation, getObservationSettingsProcedure, []string{internaljwt.TokenUseEventAccess}, true, false),
	}
	contextToken := machineOriginContext(t, internalIssuer, observation, guestService)

	result, err := newReissuer(t, keys, internalIssuer, edges).Reissue(t.Context(), reissue.Request{
		Caller:       observation,
		Procedure:    getObservationSettingsProcedure,
		ContextToken: contextToken.Token,
	})
	if err != nil {
		t.Fatalf("Reissue() error = %v, want nil", err)
	}

	if result.Origin != reissue.OriginMachineChain {
		t.Errorf("Origin = %q, want %q", result.Origin, reissue.OriginMachineChain)
	}

	claims := result.Issued.Claims

	if claims.Txn != contextToken.Claims.Txn {
		t.Errorf("txn = %q, want %q", claims.Txn, contextToken.Claims.Txn)
	}

	if claims.Scope != "" || claims.OriginSub != "" || claims.SourceJTI != "" {
		t.Errorf("scope = %q, origin_sub = %q, src_jti = %q, want all empty", claims.Scope, claims.OriginSub, claims.SourceJTI)
	}

	if claims.TenantPublicID != "" || claims.EventPublicID != "" {
		t.Errorf("tenant_id = %q, event_id = %q, want both empty", claims.TenantPublicID, claims.EventPublicID)
	}
}

func TestReissueStartsAChainForANewMachineOrigin(t *testing.T) {
	t.Parallel()

	keys := newKeys(t)
	internalIssuer := newIssuer(t, keys)
	edges := []edgepolicy.Edge{
		edge(observation, getObservationSettingsProcedure, nil, false, true),
	}
	reissuer := newReissuer(t, keys, internalIssuer, edges)
	request := reissue.Request{Caller: observation, Procedure: getObservationSettingsProcedure, ContextToken: ""}

	first, err := reissuer.Reissue(t.Context(), request)
	if err != nil {
		t.Fatalf("Reissue() error = %v, want nil", err)
	}

	second, err := reissuer.Reissue(t.Context(), request)
	if err != nil {
		t.Fatalf("Reissue() error = %v, want nil", err)
	}

	if first.Origin != reissue.OriginNewMachine {
		t.Errorf("Origin = %q, want %q", first.Origin, reissue.OriginNewMachine)
	}

	if first.Issued.Claims.Txn == "" {
		t.Errorf("txn = %q, want a new one", first.Issued.Claims.Txn)
	}

	if first.Issued.Claims.Txn == second.Issued.Claims.Txn {
		t.Errorf("txn = %q for both calls, want a new one each time", first.Issued.Claims.Txn)
	}

	if first.Issued.Claims.OriginSub != "" || first.Issued.Claims.Scope != "" {
		t.Errorf("origin_sub = %q, scope = %q, want both empty", first.Issued.Claims.OriginSub, first.Issued.Claims.Scope)
	}
}

func TestReissueRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edges        []edgepolicy.Edge
		caller       string
		procedure    string
		contextToken func(t *testing.T, keys issuer.KeyProvider, internalIssuer *issuer.Issuer) string
		want         error
	}{
		"a request without a caller": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    "",
			procedure: getEventProcedure,
			want:      reissue.ErrInvalidRequest,
		},
		"a request without a procedure": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: "",
			want:      reissue.ErrInvalidRequest,
		},
		"a caller with no edge to the procedure": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    observation,
			procedure: getEventProcedure,
			contextToken: func(t *testing.T, _ issuer.KeyProvider, internalIssuer *issuer.Issuer) string {
				t.Helper()

				return eventAccessContext(t, internalIssuer, observation).Token
			},
			want: reissue.ErrEdgeNotAllowed,
		},
		"a context token addressed to another service": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: getEventProcedure,
			contextToken: func(t *testing.T, _ issuer.KeyProvider, internalIssuer *issuer.Issuer) string {
				t.Helper()

				return eventAccessContext(t, internalIssuer, observation).Token
			},
			want: reissue.ErrInvalidContext,
		},
		"an expired context token": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: getEventProcedure,
			contextToken: func(t *testing.T, keys issuer.KeyProvider, _ *issuer.Issuer) string {
				t.Helper()

				past := newIssuer(t, keys, issuer.WithClock(func() time.Time { return time.Now().Add(-time.Hour) }))

				return eventAccessContext(t, past, graphAuthoring).Token
			},
			want: reissue.ErrInvalidContext,
		},
		"a context token that expired within the tolerated skew": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: getEventProcedure,
			contextToken: func(t *testing.T, keys issuer.KeyProvider, _ *issuer.Issuer) string {
				t.Helper()

				past := newIssuer(t, keys, issuer.WithClock(func() time.Time { return time.Now().Add(-130 * time.Second) }))

				return eventAccessContext(t, past, graphAuthoring).Token
			},
			want: reissue.ErrInvalidContext,
		},
		"a context token signed with another key": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: getEventProcedure,
			contextToken: func(t *testing.T, _ issuer.KeyProvider, _ *issuer.Issuer) string {
				t.Helper()

				return eventAccessContext(t, newIssuer(t, newKeys(t)), graphAuthoring).Token
			},
			want: reissue.ErrInvalidContext,
		},
		"no context token on an edge that requires one": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: getEventProcedure,
			want:      reissue.ErrContextRequired,
		},
		"no context token on an edge that only chains machine origins": {
			edges:     []edgepolicy.Edge{edge(observation, getObservationSettingsProcedure, nil, true, false)},
			caller:    observation,
			procedure: getObservationSettingsProcedure,
			want:      reissue.ErrContextRequired,
		},
		"a machine-origin chain on an edge that does not accept one": {
			edges:     []edgepolicy.Edge{edge(observation, getObservationSettingsProcedure, []string{internaljwt.TokenUseEventAccess}, false, true)},
			caller:    observation,
			procedure: getObservationSettingsProcedure,
			contextToken: func(t *testing.T, _ issuer.KeyProvider, internalIssuer *issuer.Issuer) string {
				t.Helper()

				return machineOriginContext(t, internalIssuer, observation, guestService).Token
			},
			want: reissue.ErrEdgeNotAllowed,
		},
		"a token use the edge does not accept": {
			edges:     []edgepolicy.Edge{edge(graphAuthoring, getEventProcedure, []string{internaljwt.TokenUseEventAccess}, false, false)},
			caller:    graphAuthoring,
			procedure: getEventProcedure,
			contextToken: func(t *testing.T, _ issuer.KeyProvider, internalIssuer *issuer.Issuer) string {
				t.Helper()

				return tenantAccessContext(t, internalIssuer, graphAuthoring).Token
			},
			want: reissue.ErrEdgeNotAllowed,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			keys := newKeys(t)
			internalIssuer := newIssuer(t, keys)

			contextToken := ""
			if tt.contextToken != nil {
				contextToken = tt.contextToken(t, keys, internalIssuer)
			}

			result, err := newReissuer(t, keys, internalIssuer, tt.edges).Reissue(t.Context(), reissue.Request{
				Caller:       tt.caller,
				Procedure:    tt.procedure,
				ContextToken: contextToken,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Reissue() error = %v, want %v", err, tt.want)
			}

			if result.Issued.Token != "" {
				t.Errorf("Reissue() issued %q, want no token", result.Issued.Token)
			}
		})
	}
}

func TestReissueDoesNotReadAnInvalidContextAsANewMachineOrigin(t *testing.T) {
	t.Parallel()

	keys := newKeys(t)
	internalIssuer := newIssuer(t, keys)
	edges := []edgepolicy.Edge{
		edge(observation, getObservationSettingsProcedure, []string{internaljwt.TokenUseEventAccess}, true, true),
	}
	foreign := eventAccessContext(t, newIssuer(t, newKeys(t)), observation)

	result, err := newReissuer(t, keys, internalIssuer, edges).Reissue(t.Context(), reissue.Request{
		Caller:       observation,
		Procedure:    getObservationSettingsProcedure,
		ContextToken: foreign.Token,
	})
	if !errors.Is(err, reissue.ErrInvalidContext) {
		t.Fatalf("Reissue() error = %v, want %v", err, reissue.ErrInvalidContext)
	}

	if result.Issued.Token != "" {
		t.Errorf("Reissue() issued %q, want no token", result.Issued.Token)
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	keys := newKeys(t)

	policy, err := edgepolicy.Build(catalog.Edges(), newRegistry(t))
	if err != nil {
		t.Fatalf("edgepolicy.Build() error = %v, want nil", err)
	}

	contexts, err := token.NewContextVerifier(gatewayIssuerID, keys)
	if err != nil {
		t.Fatalf("NewContextVerifier() error = %v, want nil", err)
	}

	tests := map[string]struct {
		build func() (*reissue.Reissuer, error)
	}{
		"without a registry": {
			build: func() (*reissue.Reissuer, error) {
				return reissue.New(nil, policy, contexts, newIssuer(t, keys))
			},
		},
		"without a policy": {
			build: func() (*reissue.Reissuer, error) {
				return reissue.New(newRegistry(t), nil, contexts, newIssuer(t, keys))
			},
		},
		"without a context verifier": {
			build: func() (*reissue.Reissuer, error) {
				return reissue.New(newRegistry(t), policy, nil, newIssuer(t, keys))
			},
		},
		"without an issuer": {
			build: func() (*reissue.Reissuer, error) {
				return reissue.New(newRegistry(t), policy, contexts, nil)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reissuer, err := tt.build()
			if !errors.Is(err, reissue.ErrMissingDependency) {
				t.Fatalf("New() error = %v, want %v", err, reissue.ErrMissingDependency)
			}

			if reissuer != nil {
				t.Errorf("New() returned a reissuer, want nil")
			}
		})
	}
}
