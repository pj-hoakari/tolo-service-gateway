package catalog

import (
	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/tolo-graph-authoring/gen/tolo/graph/v1/graphv1connect"
	"github.com/pj-hoakari/tolo-guest/gen/tolo/guest/v1/guestv1connect"
	"github.com/pj-hoakari/tolo-observation/gen/tolo/observation/v1/observationv1connect"
	"github.com/pj-hoakari/tolo-operation/gen/tolo/operation/v1/operationv1connect"
	"github.com/pj-hoakari/tolo-realtime/gen/tolo/realtime/v1/realtimev1connect"
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/relation/v1/relationv1connect"
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/tenant/v1/tenantv1connect"

	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	testBackendDestination      = "tolo-testbackend"
	tenantManagementDestination = "tolo-tenant-management"
	graphAuthoringDestination   = "tolo-graph-authoring"
	observationDestination      = "tolo-observation"
	operationDestination        = "tolo-operation"
	guestDestination            = "tolo-guest"
	realtimeDestination         = "tolo-realtime"

	graphAuthoringCaller = graphAuthoringDestination
	observationCaller    = observationDestination
	guestCaller          = guestDestination
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
		{
			Service:     graphv1connect.GraphAuthoringServiceName,
			Destination: graphAuthoringDestination,
			Policies:    graphv1connect.GraphAuthoringServicePolicies,
		},
		{
			Service:     graphv1connect.GraphSupplyServiceName,
			Destination: graphAuthoringDestination,
			Policies:    graphv1connect.GraphSupplyServicePolicies,
		},
		{
			Service:     observationv1connect.MeasurementIngestServiceName,
			Destination: observationDestination,
			Policies:    observationv1connect.MeasurementIngestServicePolicies,
		},
		{
			Service:     observationv1connect.EdgeDeviceServiceName,
			Destination: observationDestination,
			Policies:    observationv1connect.EdgeDeviceServicePolicies,
		},
		{
			Service:     observationv1connect.ObservationSettingsServiceName,
			Destination: observationDestination,
			Policies:    observationv1connect.ObservationSettingsServicePolicies,
		},
		{
			Service:     observationv1connect.StatusQueryServiceName,
			Destination: observationDestination,
			Policies:    observationv1connect.StatusQueryServicePolicies,
		},
		{
			Service:     operationv1connect.StaffCommunicationServiceName,
			Destination: operationDestination,
			Policies:    operationv1connect.StaffCommunicationServicePolicies,
		},
		{
			Service:     operationv1connect.OperationControlServiceName,
			Destination: operationDestination,
			Policies:    operationv1connect.OperationControlServicePolicies,
		},
		{
			Service:     operationv1connect.DeliveryCoordinationServiceName,
			Destination: operationDestination,
			Policies:    operationv1connect.DeliveryCoordinationServicePolicies,
		},
		{
			Service:     operationv1connect.DigestServiceName,
			Destination: operationDestination,
			Policies:    operationv1connect.DigestServicePolicies,
		},
		{
			Service:     guestv1connect.GuestPageServiceName,
			Destination: guestDestination,
			Policies:    guestv1connect.GuestPageServicePolicies,
		},
		{
			Service:     guestv1connect.GuestSettingsServiceName,
			Destination: guestDestination,
			Policies:    guestv1connect.GuestSettingsServicePolicies,
		},
		{
			Service:     realtimev1connect.RealtimeFetchServiceName,
			Destination: realtimeDestination,
			Policies:    realtimev1connect.RealtimeFetchServicePolicies,
		},
	}
}

func Overrides() registry.Overrides {
	return registry.Overrides{
		Introspection: []string{
			tenantv1connect.TenantServiceArchiveTenantProcedure,
			tenantv1connect.TenantServiceChangeTenantContractProcedure,
			relationv1connect.RelationAdminServiceCreateTenantInvitationProcedure,
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
			Procedure:           graphv1connect.GraphSupplyServiceGetCurrentRevisionProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        true,
			NewMachineOrigin:    false,
		},
		{
			Caller:              observationCaller,
			Procedure:           graphv1connect.GraphSupplyServiceGetObservationPointMappingsProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        true,
			NewMachineOrigin:    false,
		},
		{
			Caller:              observationCaller,
			Procedure:           graphv1connect.GraphSupplyServiceGetQrLocationsProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        true,
			NewMachineOrigin:    false,
		},
		{
			Caller:              observationCaller,
			Procedure:           operationv1connect.DeliveryCoordinationServiceRequestProposalDeliveryProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        true,
			NewMachineOrigin:    false,
		},
		{
			Caller:              observationCaller,
			Procedure:           operationv1connect.DeliveryCoordinationServiceRecordFeedbackValuesProcedure,
			UserOriginTokenUses: []string{internaljwt.TokenUseEventAccess},
			MachineChain:        true,
			NewMachineOrigin:    false,
		},
		{
			Caller:              guestCaller,
			Procedure:           operationv1connect.StaffCommunicationServiceListStaffMessagesProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        false,
			NewMachineOrigin:    true,
		},
		{
			Caller:              guestCaller,
			Procedure:           graphv1connect.GraphSupplyServiceGetDisplayNamesProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        false,
			NewMachineOrigin:    true,
		},
		{
			Caller:              guestCaller,
			Procedure:           graphv1connect.GraphSupplyServiceGetQrLocationsProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        false,
			NewMachineOrigin:    true,
		},
		{
			Caller:              guestCaller,
			Procedure:           graphv1connect.GraphSupplyServiceGetGuideMapLayoutProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        false,
			NewMachineOrigin:    true,
		},
		{
			Caller:              guestCaller,
			Procedure:           observationv1connect.StatusQueryServiceGetGuestSnapshotProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        false,
			NewMachineOrigin:    true,
		},
		{
			Caller:              guestCaller,
			Procedure:           observationv1connect.MeasurementIngestServiceReportMeasurementsProcedure,
			UserOriginTokenUses: nil,
			MachineChain:        false,
			NewMachineOrigin:    true,
		},
	}
}
