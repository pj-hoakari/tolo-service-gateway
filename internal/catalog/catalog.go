package catalog

import (
	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/relation/v1/relationv1connect"
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/tenant/v1/tenantv1connect"

	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	testBackendDestination      = "tolo-testbackend"
	tenantManagementDestination = "tolo-tenant-management"

	graphAuthoringCaller = "tolo-graph-authoring"
	observationCaller    = "tolo-observation"
)

func Bindings() []registry.Binding {
	return []registry.Binding{
		{
			Service:     greetv1connect.GreetServiceName,
			Destination: testBackendDestination,
			Policies:    greetv1connect.GreetServicePolicies,
		},
		{
			Service:     tenantv1connect.TenantServiceName,
			Destination: tenantManagementDestination,
			Policies:    tenantv1connect.TenantServicePolicies,
		},
		{
			Service:     relationv1connect.RelationAdminServiceName,
			Destination: tenantManagementDestination,
			Policies:    relationv1connect.RelationAdminServicePolicies,
		},
	}
}

func Overrides() registry.Overrides {
	return registry.Overrides{
		Introspection: []string{
			tenantv1connect.TenantServiceArchiveTenantProcedure,
			tenantv1connect.TenantServiceChangeTenantContractProcedure,
			relationv1connect.RelationAdminServiceAddTenantMemberProcedure,
			relationv1connect.RelationAdminServiceChangeTenantRoleProcedure,
			relationv1connect.RelationAdminServiceGrantEventRoleProcedure,
			relationv1connect.RelationAdminServiceRevokeRoleProcedure,
		},
	}
}

func Edges() []edgepolicy.Edge {
	return []edgepolicy.Edge{
		{
			Caller:              graphAuthoringCaller,
			Procedure:           tenantv1connect.TenantServiceGetEventProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        false,
			NewMachineOrigin:    false,
		},
		{
			Caller:              observationCaller,
			Procedure:           tenantv1connect.TenantServiceGetObservationSettingsProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        true,
			NewMachineOrigin:    false,
		},
	}
}
