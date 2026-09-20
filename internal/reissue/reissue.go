package reissue

import (
	"context"
	"errors"
	"fmt"
	"slices"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"

	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

var (
	ErrMissingDependency = errors.New("reissue: missing dependency")
	ErrInvalidRequest    = errors.New("reissue: invalid request")
	ErrEdgeNotAllowed    = errors.New("reissue: edge is not allowed")
	ErrUnknownProcedure  = errors.New("reissue: unknown procedure")
	ErrContextRequired   = errors.New("reissue: context token is required")
	ErrInvalidContext    = errors.New("reissue: invalid context token")
	ErrIssue             = errors.New("reissue: issue the service token")
)

type ContextVerifier interface {
	Verify(ctx context.Context, token, presenter string) (internaljwt.Claims, error)
}

type ServiceIssuer interface {
	IssueUserOriginService(ctx context.Context, input issuer.UserOriginServiceInput) (issuer.Issued, error)
	IssueMachineOriginService(ctx context.Context, input issuer.MachineOriginServiceInput) (issuer.Issued, error)
}

type Origin string

const (
	OriginUser         Origin = "user"
	OriginMachineChain Origin = "machine_chain"
	OriginNewMachine   Origin = "new_machine"
)

type Request struct {
	Caller       string
	Procedure    string
	ContextToken string
}

type Result struct {
	Issued issuer.Issued
	Edge   edgepolicy.Edge
	Origin Origin
}

type Reissuer struct {
	registry *registry.Registry
	policy   *edgepolicy.Policy
	contexts ContextVerifier
	tokens   ServiceIssuer
}

func New(reg *registry.Registry, policy *edgepolicy.Policy, contexts ContextVerifier, tokens ServiceIssuer) (*Reissuer, error) {
	if reg == nil {
		return nil, fmt.Errorf("%w: the registry is required", ErrMissingDependency)
	}

	if policy == nil {
		return nil, fmt.Errorf("%w: the edge policy is required", ErrMissingDependency)
	}

	if contexts == nil {
		return nil, fmt.Errorf("%w: the context token verifier is required", ErrMissingDependency)
	}

	if tokens == nil {
		return nil, fmt.Errorf("%w: the service token issuer is required", ErrMissingDependency)
	}

	return &Reissuer{registry: reg, policy: policy, contexts: contexts, tokens: tokens}, nil
}

func (r *Reissuer) Reissue(ctx context.Context, req Request) (Result, error) {
	var zero Result

	if req.Caller == "" {
		return zero, fmt.Errorf("%w: the caller is required", ErrInvalidRequest)
	}

	if req.Procedure == "" {
		return zero, fmt.Errorf("%w: the procedure is required", ErrInvalidRequest)
	}

	edge, allowed := r.policy.Lookup(req.Caller, req.Procedure)
	if !allowed {
		return zero, fmt.Errorf("%w: %s may not call %s", ErrEdgeNotAllowed, req.Caller, req.Procedure)
	}

	entry, registered := r.registry.Lookup(req.Procedure)
	if !registered {
		return zero, fmt.Errorf("%w: %s is not registered", ErrUnknownProcedure, req.Procedure)
	}

	if req.ContextToken == "" {
		return r.newMachineOrigin(ctx, req.Caller, entry.Destination, edge)
	}

	claims, err := r.contexts.Verify(ctx, req.ContextToken, req.Caller)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrInvalidContext, err)
	}

	if isUserOrigin(claims) {
		return r.userOrigin(ctx, req.Caller, entry.Destination, edge, claims)
	}

	if claims.TokenUse == internaljwt.TokenUseService {
		return r.machineChain(ctx, req.Caller, entry.Destination, edge, claims)
	}

	return zero, fmt.Errorf("%w: the token use %q starts no service call", ErrInvalidContext, claims.TokenUse)
}

func isUserOrigin(claims internaljwt.Claims) bool {
	switch claims.TokenUse {
	case internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess, internaljwt.TokenUseRegistration:
		return true
	case internaljwt.TokenUseService:
		return claims.OriginSub != ""
	default:
		return false
	}
}

func (r *Reissuer) newMachineOrigin(ctx context.Context, caller, audience string, edge edgepolicy.Edge) (Result, error) {
	var zero Result

	if !edge.NewMachineOrigin {
		return zero, fmt.Errorf("%w: %s to %s accepts no new machine origin", ErrContextRequired, caller, edge.Procedure)
	}

	issued, err := r.tokens.IssueMachineOriginService(ctx, issuer.MachineOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       nil,
	})
	if err != nil {
		return zero, wrapIssue(err)
	}

	return Result{Issued: issued, Edge: edge, Origin: OriginNewMachine}, nil
}

func (r *Reissuer) userOrigin(ctx context.Context, caller, audience string, edge edgepolicy.Edge, claims internaljwt.Claims) (Result, error) {
	var zero Result

	if !slices.Contains(edge.UserOriginTokenUses, claims.TokenUse) {
		return zero, fmt.Errorf("%w: %s to %s accepts no %s context", ErrEdgeNotAllowed, caller, edge.Procedure, claims.TokenUse)
	}

	issued, err := r.tokens.IssueUserOriginService(ctx, issuer.UserOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       claims,
	})
	if err != nil {
		return zero, wrapIssue(err)
	}

	return Result{Issued: issued, Edge: edge, Origin: OriginUser}, nil
}

func (r *Reissuer) machineChain(ctx context.Context, caller, audience string, edge edgepolicy.Edge, claims internaljwt.Claims) (Result, error) {
	var zero Result

	if !edge.MachineChain {
		return zero, fmt.Errorf("%w: %s to %s accepts no machine-origin chain", ErrEdgeNotAllowed, caller, edge.Procedure)
	}

	issued, err := r.tokens.IssueMachineOriginService(ctx, issuer.MachineOriginServiceInput{
		Audience:      audience,
		CallerService: caller,
		Context:       &claims,
	})
	if err != nil {
		return zero, wrapIssue(err)
	}

	return Result{Issued: issued, Edge: edge, Origin: OriginMachineChain}, nil
}

func wrapIssue(err error) error {
	if errors.Is(err, issuer.ErrContextExpired) {
		return fmt.Errorf("%w: %w", ErrInvalidContext, err)
	}

	return fmt.Errorf("%w: %w", ErrIssue, err)
}
