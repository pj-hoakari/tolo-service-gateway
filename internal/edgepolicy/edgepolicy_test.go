package edgepolicy_test

import (
	"errors"
	"slices"
	"testing"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	getEventProcedure               = "/tolo.tenant.v1.TenantService/GetEvent"
	getObservationSettingsProcedure = "/tolo.tenant.v1.TenantService/GetObservationSettings"
	listEventsProcedure             = "/tolo.tenant.v1.TenantService/ListEvents"
	unknownProcedure                = "/tolo.tenant.v1.TenantService/Unknown"

	graphAuthoring   = "tolo-graph-authoring"
	observation      = "tolo-observation"
	tenantManagement = "tolo-tenant-management"
)

func buildRegistry(t *testing.T) *registry.Registry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("registry.Build() error = %v, want nil", err)
	}

	return built
}

func userOriginEdge(caller, procedure string, tokenUses ...string) edgepolicy.Edge {
	return edgepolicy.Edge{
		Caller:              caller,
		Procedure:           procedure,
		UserOriginTokenUses: tokenUses,
		MachineChain:        false,
		NewMachineOrigin:    false,
	}
}

func TestBuildAcceptsDeclaredEdges(t *testing.T) {
	t.Parallel()

	edges := []edgepolicy.Edge{
		{
			Caller:              observation,
			Procedure:           getObservationSettingsProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess, internaljwt.TokenUseService},
			MachineChain:        true,
			NewMachineOrigin:    true,
		},
		userOriginEdge(graphAuthoring, getEventProcedure, internaljwt.TokenUseEventAccess),
	}

	policy, err := edgepolicy.Build(edges, buildRegistry(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	edge, found := policy.Lookup(graphAuthoring, getEventProcedure)
	if !found {
		t.Fatalf("Lookup(%q, %q) found no edge, want one", graphAuthoring, getEventProcedure)
	}

	if !slices.Equal(edge.UserOriginTokenUses, []string{internaljwt.TokenUseEventAccess}) {
		t.Errorf("UserOriginTokenUses = %v, want [%q]", edge.UserOriginTokenUses, internaljwt.TokenUseEventAccess)
	}

	if _, found := policy.Lookup(observation, getEventProcedure); found {
		t.Errorf("Lookup(%q, %q) found an edge, want none", observation, getEventProcedure)
	}

	got := policy.Edges()
	if len(got) != 2 {
		t.Fatalf("Edges() returned %d edges, want 2", len(got))
	}

	if got[0].Caller != graphAuthoring || got[1].Caller != observation {
		t.Errorf("Edges() callers = %q, %q, want %q, %q", got[0].Caller, got[1].Caller, graphAuthoring, observation)
	}
}

func TestBuildRejectsInvalidEdges(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		edges []edgepolicy.Edge
		want  error
	}{
		"an edge without a caller": {
			edges: []edgepolicy.Edge{userOriginEdge("", getEventProcedure, internaljwt.TokenUseEventAccess)},
			want:  edgepolicy.ErrInvalidEdge,
		},
		"an edge without a procedure": {
			edges: []edgepolicy.Edge{userOriginEdge(graphAuthoring, "", internaljwt.TokenUseEventAccess)},
			want:  edgepolicy.ErrInvalidEdge,
		},
		"the same caller and procedure twice": {
			edges: []edgepolicy.Edge{
				userOriginEdge(graphAuthoring, getEventProcedure, internaljwt.TokenUseEventAccess),
				userOriginEdge(graphAuthoring, getEventProcedure, internaljwt.TokenUseTenantAccess),
			},
			want: edgepolicy.ErrDuplicateEdge,
		},
		"a procedure the registry does not know": {
			edges: []edgepolicy.Edge{userOriginEdge(graphAuthoring, unknownProcedure, internaljwt.TokenUseEventAccess)},
			want:  edgepolicy.ErrUnknownProcedure,
		},
		"a procedure that accepts no service subject": {
			edges: []edgepolicy.Edge{userOriginEdge(graphAuthoring, listEventsProcedure, internaljwt.TokenUseEventAccess)},
			want:  edgepolicy.ErrProcedureNotService,
		},
		"a caller that is the destination itself": {
			edges: []edgepolicy.Edge{userOriginEdge(tenantManagement, getEventProcedure, internaljwt.TokenUseEventAccess)},
			want:  edgepolicy.ErrSelfEdge,
		},
		"an edge that accepts no origin": {
			edges: []edgepolicy.Edge{userOriginEdge(graphAuthoring, getEventProcedure)},
			want:  edgepolicy.ErrNoAcceptedOrigin,
		},
		"an unknown token use": {
			edges: []edgepolicy.Edge{userOriginEdge(graphAuthoring, getEventProcedure, "tenant_write")},
			want:  edgepolicy.ErrInvalidTokenUse,
		},
		"the same token use twice": {
			edges: []edgepolicy.Edge{
				userOriginEdge(graphAuthoring, getEventProcedure, internaljwt.TokenUseEventAccess, internaljwt.TokenUseEventAccess),
			},
			want: edgepolicy.ErrInvalidTokenUse,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			policy, err := edgepolicy.Build(tt.edges, buildRegistry(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Build() error = %v, want %v", err, tt.want)
			}

			if policy != nil {
				t.Errorf("Build() returned a policy, want nil")
			}
		})
	}
}

func TestBuildWithoutARegistry(t *testing.T) {
	t.Parallel()

	policy, err := edgepolicy.Build(nil, nil)
	if !errors.Is(err, edgepolicy.ErrMissingRegistry) {
		t.Fatalf("Build() error = %v, want %v", err, edgepolicy.ErrMissingRegistry)
	}

	if policy != nil {
		t.Errorf("Build() returned a policy, want nil")
	}
}

func TestBuildReportsEveryInvalidEdge(t *testing.T) {
	t.Parallel()

	edges := []edgepolicy.Edge{
		userOriginEdge("", getEventProcedure, internaljwt.TokenUseEventAccess),
		userOriginEdge(graphAuthoring, listEventsProcedure, internaljwt.TokenUseEventAccess),
		userOriginEdge(observation, getObservationSettingsProcedure, "tenant_write"),
	}

	_, err := edgepolicy.Build(edges, buildRegistry(t))

	for _, want := range []error{edgepolicy.ErrInvalidEdge, edgepolicy.ErrProcedureNotService, edgepolicy.ErrInvalidTokenUse} {
		if !errors.Is(err, want) {
			t.Errorf("Build() error = %v, want it to report %v", err, want)
		}
	}
}

func TestBuildCopiesTheDeclaredEdges(t *testing.T) {
	t.Parallel()

	tokenUses := []string{internaljwt.TokenUseEventAccess}
	edges := []edgepolicy.Edge{userOriginEdge(graphAuthoring, getEventProcedure, tokenUses...)}

	policy, err := edgepolicy.Build(edges, buildRegistry(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	edges[0].Caller = observation
	tokenUses[0] = internaljwt.TokenUseTenantAccess

	edge, found := policy.Lookup(graphAuthoring, getEventProcedure)
	if !found {
		t.Fatalf("Lookup(%q, %q) found no edge, want one", graphAuthoring, getEventProcedure)
	}

	if !slices.Equal(edge.UserOriginTokenUses, []string{internaljwt.TokenUseEventAccess}) {
		t.Errorf("UserOriginTokenUses = %v, want [%q]", edge.UserOriginTokenUses, internaljwt.TokenUseEventAccess)
	}

	edge.UserOriginTokenUses[0] = internaljwt.TokenUseTenantAccess

	again, _ := policy.Lookup(graphAuthoring, getEventProcedure)
	if !slices.Equal(again.UserOriginTokenUses, []string{internaljwt.TokenUseEventAccess}) {
		t.Errorf("UserOriginTokenUses = %v, want [%q]", again.UserOriginTokenUses, internaljwt.TokenUseEventAccess)
	}
}

func TestSnapshotListsEveryEdgeInOrder(t *testing.T) {
	t.Parallel()

	edges := []edgepolicy.Edge{
		{
			Caller:              observation,
			Procedure:           getObservationSettingsProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        true,
			NewMachineOrigin:    true,
		},
		{
			Caller:              graphAuthoring,
			Procedure:           getEventProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess, internaljwt.TokenUseService},
			MachineChain:        false,
			NewMachineOrigin:    false,
		},
	}

	policy, err := edgepolicy.Build(edges, buildRegistry(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	want := "tolo-graph-authoring\t/tolo.tenant.v1.TenantService/GetEvent\tuser_origin=event_access,service\tmachine_chain=false\tnew_machine_origin=false\n" +
		"tolo-observation\t/tolo.tenant.v1.TenantService/GetObservationSettings\tuser_origin=-\tmachine_chain=true\tnew_machine_origin=true\n"

	if got := policy.Snapshot(); got != want {
		t.Errorf("Snapshot() = %q, want %q", got, want)
	}
}

func TestSnapshotOfAnEmptyPolicy(t *testing.T) {
	t.Parallel()

	policy, err := edgepolicy.Build(nil, buildRegistry(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	if got := policy.Snapshot(); got != "" {
		t.Errorf("Snapshot() = %q, want %q", got, "")
	}
}
