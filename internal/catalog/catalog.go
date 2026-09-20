package catalog

import (
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/relation/v1/relationv1connect"
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/tenant/v1/tenantv1connect"

	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	testBackendDestination      = "tolo-testbackend"
	tenantManagementDestination = "tolo-tenant-management"
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
