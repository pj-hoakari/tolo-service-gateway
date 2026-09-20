package edgepolicy

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

var (
	ErrMissingRegistry     = errors.New("edgepolicy: registry is required")
	ErrInvalidEdge         = errors.New("edgepolicy: invalid edge")
	ErrDuplicateEdge       = errors.New("edgepolicy: duplicate edge")
	ErrUnknownProcedure    = errors.New("edgepolicy: unknown procedure")
	ErrProcedureNotService = errors.New("edgepolicy: procedure accepts no service subject")
	ErrSelfEdge            = errors.New("edgepolicy: self edge")
	ErrNoAcceptedOrigin    = errors.New("edgepolicy: no accepted origin")
	ErrInvalidTokenUse     = errors.New("edgepolicy: invalid token use")
)

const emptyListMark = "-"

type Edge struct {
	Caller              string
	Procedure           string
	UserOriginTokenUses []string
	MachineChain        bool
	NewMachineOrigin    bool
}

type edgeKey struct {
	caller    string
	procedure string
}

type Policy struct {
	edges map[edgeKey]Edge
	order []edgeKey
}

func Build(edges []Edge, reg *registry.Registry) (*Policy, error) {
	if reg == nil {
		return nil, ErrMissingRegistry
	}

	built := make(map[edgeKey]Edge, len(edges))
	seen := make(map[edgeKey]struct{}, len(edges))

	var errs []error

	for index, edge := range edges {
		if err := checkEdge(index, edge, reg, seen); err != nil {
			errs = append(errs, err)

			continue
		}

		key := keyOf(edge)
		seen[key] = struct{}{}
		built[key] = cloneEdge(edge)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return &Policy{edges: built, order: slices.SortedFunc(maps.Keys(built), compareKeys)}, nil
}

func checkEdge(index int, edge Edge, reg *registry.Registry, seen map[edgeKey]struct{}) error {
	if edge.Caller == "" {
		return fmt.Errorf("%w: edge %d declares no caller", ErrInvalidEdge, index+1)
	}

	if edge.Procedure == "" {
		return fmt.Errorf("%w: edge %d declares no procedure", ErrInvalidEdge, index+1)
	}

	if _, duplicate := seen[keyOf(edge)]; duplicate {
		return fmt.Errorf("%w: %s to %s is declared more than once", ErrDuplicateEdge, edge.Caller, edge.Procedure)
	}

	entry, registered := reg.Lookup(edge.Procedure)
	if !registered {
		return fmt.Errorf("%w: %s is not registered", ErrUnknownProcedure, edge.Procedure)
	}

	if !entry.Service {
		return fmt.Errorf("%w: %s accepts no service subject", ErrProcedureNotService, edge.Procedure)
	}

	if edge.Caller == entry.Destination {
		return fmt.Errorf("%w: %s calls itself at %s", ErrSelfEdge, edge.Caller, edge.Procedure)
	}

	if err := checkTokenUses(edge); err != nil {
		return err
	}

	if len(edge.UserOriginTokenUses) == 0 && !edge.MachineChain && !edge.NewMachineOrigin {
		return fmt.Errorf("%w: %s to %s accepts no origin", ErrNoAcceptedOrigin, edge.Caller, edge.Procedure)
	}

	return nil
}

func checkTokenUses(edge Edge) error {
	seen := make(map[string]struct{}, len(edge.UserOriginTokenUses))

	for _, tokenUse := range edge.UserOriginTokenUses {
		if !isKnownTokenUse(tokenUse) {
			return fmt.Errorf("%w: %s to %s declares the unknown token use %q", ErrInvalidTokenUse, edge.Caller, edge.Procedure, tokenUse)
		}

		if _, duplicate := seen[tokenUse]; duplicate {
			return fmt.Errorf("%w: %s to %s declares the token use %q more than once", ErrInvalidTokenUse, edge.Caller, edge.Procedure, tokenUse)
		}

		seen[tokenUse] = struct{}{}
	}

	return nil
}

func isKnownTokenUse(tokenUse string) bool {
	switch tokenUse {
	case internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess, internaljwt.TokenUseService, internaljwt.TokenUseRegistration:
		return true
	default:
		return false
	}
}

func (p *Policy) Lookup(caller, procedure string) (Edge, bool) {
	edge, ok := p.edges[edgeKey{caller: caller, procedure: procedure}]
	if !ok {
		var zero Edge

		return zero, false
	}

	return cloneEdge(edge), true
}

func (p *Policy) Edges() []Edge {
	edges := make([]Edge, 0, len(p.order))

	for _, key := range p.order {
		edges = append(edges, cloneEdge(p.edges[key]))
	}

	return edges
}

func (p *Policy) Snapshot() string {
	lines := make([]string, 0, len(p.order))

	for _, key := range p.order {
		edge := p.edges[key]
		lines = append(lines, strings.Join([]string{
			edge.Caller,
			edge.Procedure,
			"user_origin=" + formatList(edge.UserOriginTokenUses),
			fmt.Sprintf("machine_chain=%t", edge.MachineChain),
			fmt.Sprintf("new_machine_origin=%t", edge.NewMachineOrigin),
		}, "\t"))
	}

	if len(lines) == 0 {
		return ""
	}

	return strings.Join(lines, "\n") + "\n"
}

func keyOf(edge Edge) edgeKey {
	return edgeKey{caller: edge.Caller, procedure: edge.Procedure}
}

func compareKeys(a, b edgeKey) int {
	return cmp.Or(cmp.Compare(a.caller, b.caller), cmp.Compare(a.procedure, b.procedure))
}

func cloneEdge(edge Edge) Edge {
	edge.UserOriginTokenUses = slices.Clone(edge.UserOriginTokenUses)

	return edge
}

func formatList(values []string) string {
	if len(values) == 0 {
		return emptyListMark
	}

	return strings.Join(values, ",")
}
