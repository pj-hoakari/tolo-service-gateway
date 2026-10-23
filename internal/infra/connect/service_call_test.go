package connect_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/golang-jwt/jwt/v5"
	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
	graphv1 "github.com/pj-hoakari/tolo-graph-authoring/gen/tolo/graph/v1"
	"github.com/pj-hoakari/tolo-graph-authoring/gen/tolo/graph/v1/graphv1connect"
	guestv1 "github.com/pj-hoakari/tolo-guest/gen/tolo/guest/v1"
	"github.com/pj-hoakari/tolo-guest/gen/tolo/guest/v1/guestv1connect"
	observationv1 "github.com/pj-hoakari/tolo-observation/gen/tolo/observation/v1"
	"github.com/pj-hoakari/tolo-observation/gen/tolo/observation/v1/observationv1connect"
	operationv1 "github.com/pj-hoakari/tolo-operation/gen/tolo/operation/v1"
	"github.com/pj-hoakari/tolo-operation/gen/tolo/operation/v1/operationv1connect"
	tenantv1 "github.com/pj-hoakari/tolo-tenant-management/gen/tolo/tenant/v1"
	"github.com/pj-hoakari/tolo-tenant-management/gen/tolo/tenant/v1/tenantv1connect"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/config"
	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	infraconnect "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forward"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forwardgen"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
	"github.com/pj-hoakari/tolo-service-gateway/internal/reissue"
	"github.com/pj-hoakari/tolo-service-gateway/internal/token"
)

const (
	graphAuthoring   = "tolo-graph-authoring"
	observation      = "tolo-observation"
	operation        = "tolo-operation"
	guest            = "tolo-guest"
	tenantManagement = "tolo-tenant-management"
	contextEventID   = "0f1e2d3c4b5a6978"
	contextScope     = "events.manage"
)

type upstreamTenantService struct {
	tenantv1connect.UnimplementedTenantServiceHandler
	calls chan http.Header
}

func (s upstreamTenantService) GetEvent(ctx context.Context, _ *tenantv1.GetEventRequest) (*tenantv1.GetEventResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &tenantv1.GetEventResponse{}, nil
}

type upstreamGraphSupplyService struct {
	graphv1connect.UnimplementedGraphSupplyServiceHandler
	calls chan http.Header
}

func (s upstreamGraphSupplyService) GetObservationPointMappings(
	ctx context.Context,
	_ *graphv1.GetMappingsRequest,
) (*graphv1.GetMappingsResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &graphv1.GetMappingsResponse{}, nil
}

func (s upstreamGraphSupplyService) GetDisplayNames(
	ctx context.Context,
	_ *graphv1.GetDisplayNamesRequest,
) (*graphv1.GetDisplayNamesResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &graphv1.GetDisplayNamesResponse{}, nil
}

func (s upstreamGraphSupplyService) GetQrLocations(
	ctx context.Context,
	_ *graphv1.GetQrLocationsRequest,
) (*graphv1.GetQrLocationsResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &graphv1.GetQrLocationsResponse{}, nil
}

type upstreamStatusQueryService struct {
	observationv1connect.UnimplementedStatusQueryServiceHandler
	calls chan http.Header
}

func (s upstreamStatusQueryService) GetGuestSnapshot(
	ctx context.Context,
	_ *observationv1.GetGuestSnapshotRequest,
) (*observationv1.GetGuestSnapshotResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &observationv1.GetGuestSnapshotResponse{}, nil
}

type upstreamMeasurementIngestService struct {
	observationv1connect.UnimplementedMeasurementIngestServiceHandler
	calls chan http.Header
}

func (s upstreamMeasurementIngestService) ReportMeasurements(
	ctx context.Context,
	_ *observationv1.ReportMeasurementsRequest,
) (*observationv1.ReportMeasurementsResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &observationv1.ReportMeasurementsResponse{}, nil
}

type upstreamGuestPageService struct {
	guestv1connect.UnimplementedGuestPageServiceHandler
	calls chan http.Header
}

func (s upstreamGuestPageService) OpenGuestPage(
	ctx context.Context,
	_ *guestv1.OpenGuestPageRequest,
) (*guestv1.OpenGuestPageResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &guestv1.OpenGuestPageResponse{}, nil
}

type upstreamGuestSettingsService struct {
	guestv1connect.UnimplementedGuestSettingsServiceHandler
	calls chan http.Header
}

func (s upstreamGuestSettingsService) GetGuestSettings(
	ctx context.Context,
	_ *guestv1.GetGuestSettingsRequest,
) (*guestv1.GuestSettings, error) {
	s.calls <- requestHeaderOf(ctx)

	return &guestv1.GuestSettings{}, nil
}

type upstreamStaffCommunicationService struct {
	operationv1connect.UnimplementedStaffCommunicationServiceHandler
	calls chan http.Header
}

func (s upstreamStaffCommunicationService) ListStaffMessages(
	ctx context.Context,
	_ *operationv1.ListStaffMessagesRequest,
) (*operationv1.ListStaffMessagesResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &operationv1.ListStaffMessagesResponse{}, nil
}

type upstreamDeliveryCoordinationService struct {
	operationv1connect.UnimplementedDeliveryCoordinationServiceHandler
	calls chan http.Header
}

func (s upstreamDeliveryCoordinationService) RequestProposalDelivery(
	ctx context.Context,
	_ *operationv1.RequestProposalDeliveryRequest,
) (*operationv1.RequestProposalDeliveryResponse, error) {
	s.calls <- requestHeaderOf(ctx)

	return &operationv1.RequestProposalDeliveryResponse{}, nil
}

type serviceFixture struct {
	tenants    tenantv1connect.TenantServiceClient
	graphs     graphv1connect.GraphSupplyServiceClient
	staff      operationv1connect.StaffCommunicationServiceClient
	deliveries    operationv1connect.DeliveryCoordinationServiceClient
	statuses      observationv1connect.StatusQueryServiceClient
	measurements  observationv1connect.MeasurementIngestServiceClient
	guestPages    guestv1connect.GuestPageServiceClient
	guestSettings guestv1connect.GuestSettingsServiceClient
	issuer        *issuer.Issuer
	backend       *verifier.ContextVerifier
	upstream      chan http.Header
	audit         *bytes.Buffer
}

func newServiceGateway(t *testing.T, inbound config.Inbound) serviceFixture {
	t.Helper()

	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	keys := gatewayKeyProvider{keys: issuer.KeySet{
		Signing:   issuer.SigningKey{KeyID: gatewaySigningKeyID, Key: signing},
		Published: nil,
	}}

	gatewayIssuer, err := issuer.New(gatewayIssuerID, keys)
	if err != nil {
		t.Fatalf("issuer.New() error = %v, want nil", err)
	}

	contexts, err := token.NewContextVerifier(gatewayIssuerID, keys)
	if err != nil {
		t.Fatalf("NewContextVerifier() error = %v, want nil", err)
	}

	built := newRegistry(t)

	policy, err := edgepolicy.Build(catalog.Edges(), built)
	if err != nil {
		t.Fatalf("edgepolicy.Build() error = %v, want nil", err)
	}

	reissuer, err := reissue.New(built, policy, contexts, gatewayIssuer)
	if err != nil {
		t.Fatalf("reissue.New() error = %v, want nil", err)
	}

	calls := make(chan http.Header, 8)

	mux := http.NewServeMux()
	server := connectrpc.NewServer()
	tenantv1connect.RegisterTenantServiceHandler(server, upstreamTenantService{
		UnimplementedTenantServiceHandler: tenantv1connect.UnimplementedTenantServiceHandler{},
		calls:                             calls,
	})
	graphv1connect.RegisterGraphSupplyServiceHandler(server, upstreamGraphSupplyService{
		UnimplementedGraphSupplyServiceHandler: graphv1connect.UnimplementedGraphSupplyServiceHandler{},
		calls:                                  calls,
	})
	operationv1connect.RegisterStaffCommunicationServiceHandler(server, upstreamStaffCommunicationService{
		UnimplementedStaffCommunicationServiceHandler: operationv1connect.UnimplementedStaffCommunicationServiceHandler{},
		calls: calls,
	})
	operationv1connect.RegisterDeliveryCoordinationServiceHandler(server, upstreamDeliveryCoordinationService{
		UnimplementedDeliveryCoordinationServiceHandler: operationv1connect.UnimplementedDeliveryCoordinationServiceHandler{},
		calls: calls,
	})
	observationv1connect.RegisterStatusQueryServiceHandler(server, upstreamStatusQueryService{
		UnimplementedStatusQueryServiceHandler: observationv1connect.UnimplementedStatusQueryServiceHandler{},
		calls:                                  calls,
	})
	observationv1connect.RegisterMeasurementIngestServiceHandler(server, upstreamMeasurementIngestService{
		UnimplementedMeasurementIngestServiceHandler: observationv1connect.UnimplementedMeasurementIngestServiceHandler{},
		calls: calls,
	})
	guestv1connect.RegisterGuestPageServiceHandler(server, upstreamGuestPageService{
		UnimplementedGuestPageServiceHandler: guestv1connect.UnimplementedGuestPageServiceHandler{},
		calls:                                calls,
	})
	guestv1connect.RegisterGuestSettingsServiceHandler(server, upstreamGuestSettingsService{
		UnimplementedGuestSettingsServiceHandler: guestv1connect.UnimplementedGuestSettingsServiceHandler{},
		calls:                                    calls,
	})
	connecthttp.Mount(mux, server)

	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)

	handlers, err := forward.Handlers(
		catalog.Bindings(),
		destinationsTo(t, upstream.URL),
		forwardgen.Mounts(),
		forward.NewHTTPClient(http.DefaultTransport),
		[]connectrpc.ClientInterceptor{forward.AuthorizationInterceptor()},
		[]connectrpc.ServerInterceptor{infraconnect.AuditInterceptor()},
	)
	if err != nil {
		t.Fatalf("Handlers() error = %v, want nil", err)
	}

	logs := &bytes.Buffer{}

	gateway := httptest.NewServer(httpapi.NewHandler(infraconnect.Routes(infraconnect.Config{
		Inbound:  inbound,
		Registry: built,
		Handlers: handlers,
		Audit: audit.NewEmitter(logging.NewLogger(logs, logging.Options{
			Level:     slog.LevelInfo,
			AddSource: false,
			ProjectID: "",
		})),
		Authenticator:    newAuthenticator(),
		Issuer:           gatewayIssuer,
		Reissuer:         reissuer,
		TracerProvider:   sdktrace.NewTracerProvider(),
		TrustedProxyHops: 0,
	})))
	t.Cleanup(gateway.Close)

	client := connectrpc.NewClient(connecthttp.NewTransport(gateway.Client(), gateway.URL))

	return serviceFixture{
		tenants:    tenantv1connect.NewTenantServiceClient(client),
		graphs:     graphv1connect.NewGraphSupplyServiceClient(client),
		staff:      operationv1connect.NewStaffCommunicationServiceClient(client),
		deliveries:    operationv1connect.NewDeliveryCoordinationServiceClient(client),
		statuses:      observationv1connect.NewStatusQueryServiceClient(client),
		measurements:  observationv1connect.NewMeasurementIngestServiceClient(client),
		guestPages:    guestv1connect.NewGuestPageServiceClient(client),
		guestSettings: guestv1connect.NewGuestSettingsServiceClient(client),
		issuer:        gatewayIssuer,
		backend:       contexts,
		upstream:      calls,
		audit:         logs,
	}
}

func (f serviceFixture) eventAccessFor(t *testing.T, audience string) issuer.Issued {
	t.Helper()

	issued, err := f.issuer.IssueFromExternal(t.Context(), issuer.ExternalTokenInput{
		Audience:        audience,
		TokenUse:        internaljwt.TokenUseEventAccess,
		Subject:         externalSubject,
		ClientID:        externalClientID,
		Scope:           contextScope,
		SourceJTI:       externalJTI,
		SourceExpiresAt: time.Now().Add(15 * time.Minute),
		TenantPublicID:  externalTenantID,
		EventPublicID:   contextEventID,
	})
	if err != nil {
		t.Fatalf("IssueFromExternal() error = %v, want nil", err)
	}

	return issued
}

func (f serviceFixture) machineOriginFor(t *testing.T, audience string) issuer.Issued {
	t.Helper()

	issued, err := f.issuer.IssueMachineOriginService(t.Context(), issuer.MachineOriginServiceInput{
		Audience:      audience,
		CallerService: guest,
		Context:       nil,
	})
	if err != nil {
		t.Fatalf("IssueMachineOriginService() error = %v, want nil", err)
	}

	return issued
}

func (f serviceFixture) forwarded(t *testing.T, audience string) (http.Header, internaljwt.Claims) {
	t.Helper()

	var header http.Header

	select {
	case header = <-f.upstream:
	default:
		t.Fatal("the upstream was not called")
	}

	claims, err := f.backend.Verify(t.Context(), strings.TrimPrefix(header.Get("Authorization"), "Bearer "), audience)
	if err != nil {
		t.Fatalf("the upstream could not verify the forwarded token: %v", err)
	}

	return header, claims
}

func (f serviceFixture) assertNotForwarded(t *testing.T) {
	t.Helper()

	if got := len(f.upstream); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}

func getEvent(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.tenants.GetEvent(ctx, &tenantv1.GetEventRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func getObservationPointMappings(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.graphs.GetObservationPointMappings(ctx, &graphv1.GetMappingsRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func listStaffMessages(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.staff.ListStaffMessages(ctx, &operationv1.ListStaffMessagesRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func requestProposalDelivery(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.deliveries.RequestProposalDelivery(ctx, &operationv1.RequestProposalDeliveryRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func getDisplayNames(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.graphs.GetDisplayNames(ctx, &graphv1.GetDisplayNamesRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func getQrLocations(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.graphs.GetQrLocations(ctx, &graphv1.GetQrLocationsRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func getGuestSnapshot(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.statuses.GetGuestSnapshot(ctx, &observationv1.GetGuestSnapshotRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func reportMeasurements(t *testing.T, f serviceFixture, header map[string]string) error {
	t.Helper()

	ctx, info := connectrpc.NewClientContext(t.Context())
	for key, value := range header {
		info.RequestHeader().Set(key, value)
	}

	_, err := f.measurements.ReportMeasurements(ctx, &observationv1.ReportMeasurementsRequest{EventId: contextEventID})

	return err //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func bearerHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func TestInternalListenerReissuesAGraphAuthoringEventContext(t *testing.T) {
	t.Parallel()

	f := newServiceGateway(t, config.InboundInternal)
	presented := f.eventAccessFor(t, graphAuthoring)

	if err := getEvent(t, f, bearerHeader(presented.Token)); err != nil {
		t.Fatalf("GetEvent() error = %v, want nil", err)
	}

	header, claims := f.forwarded(t, tenantManagement)

	if header.Get("Authorization") == "Bearer "+presented.Token {
		t.Error("the upstream received the context token, want a reissued token")
	}

	want := map[string]string{
		"token_use":  internaljwt.TokenUseService,
		"aud":        tenantManagement,
		"sub":        graphAuthoring,
		"client_id":  graphAuthoring,
		"event_id":   contextEventID,
		"tenant_id":  externalTenantID,
		"scope":      contextScope,
		"src_jti":    presented.Claims.ID,
		"origin_sub": externalSubject,
		"txn":        presented.Claims.Txn,
	}
	got := map[string]string{
		"token_use":  claims.TokenUse,
		"aud":        strings.Join(claims.Audience, " "),
		"sub":        claims.Subject,
		"client_id":  claims.ClientID,
		"event_id":   claims.EventPublicID,
		"tenant_id":  claims.TenantPublicID,
		"scope":      claims.Scope,
		"src_jti":    claims.SourceJTI,
		"origin_sub": claims.OriginSub,
		"txn":        claims.Txn,
	}

	for key, value := range want {
		if got[key] != value {
			t.Errorf("forwarded %s = %q, want %q", key, got[key], value)
		}
	}

	if claims.ID == "" || claims.ID == presented.Claims.ID {
		t.Errorf("forwarded jti = %q, want a new jti", claims.ID)
	}

	record := singleAuditRecord(t, f.audit)

	assertAudit(t, record, map[string]any{
		"method":         tenantv1connect.TenantServiceGetEventProcedure,
		"result":         "ok",
		"caller_service": graphAuthoring,
		"origin":         "user",
		"sub":            graphAuthoring,
		"client_id":      graphAuthoring,
		"token_use":      internaljwt.TokenUseService,
		"txn":            presented.Claims.Txn,
		"jti":            claims.ID,
		"src_jti":        presented.Claims.ID,
		"origin_sub":     externalSubject,
	})
	assertCorrelated(t, record)
}

func TestInternalListenerForwardsNoIncomingCredential(t *testing.T) {
	t.Parallel()

	f := newServiceGateway(t, config.InboundInternal)

	header := bearerHeader(f.eventAccessFor(t, graphAuthoring).Token)
	header["X-Serverless-Authorization"] = "Bearer google-id-token"

	if err := getEvent(t, f, header); err != nil {
		t.Fatalf("GetEvent() error = %v, want nil", err)
	}

	forwarded, _ := f.forwarded(t, tenantManagement)

	if got := forwarded.Values("Authorization"); len(got) != 1 {
		t.Errorf("forwarded Authorization = %q, want only the reissued token", got)
	}

	for _, name := range []string{"Tolo-Caller-Service", "X-Serverless-Authorization"} {
		if got, ok := forwarded[name]; ok {
			t.Errorf("forwarded %s = %q, want none", name, got)
		}
	}
}

func TestInternalListenerReissuesObservationContexts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		context    func(f serviceFixture, t *testing.T) issuer.Issued
		wantOrigin string
	}{
		"an event context": {
			context: func(f serviceFixture, t *testing.T) issuer.Issued {
				t.Helper()

				return f.eventAccessFor(t, observation)
			},
			wantOrigin: "user",
		},
		"a machine-origin chain": {
			context: func(f serviceFixture, t *testing.T) issuer.Issued {
				t.Helper()

				return f.machineOriginFor(t, observation)
			},
			wantOrigin: "machine_chain",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newServiceGateway(t, config.InboundInternal)
			presented := test.context(f, t)

			if err := getObservationPointMappings(t, f, bearerHeader(presented.Token)); err != nil {
				t.Fatalf("GetObservationPointMappings() error = %v, want nil", err)
			}

			_, claims := f.forwarded(t, graphAuthoring)

			if claims.Subject != observation || claims.TokenUse != internaljwt.TokenUseService || claims.Txn != presented.Claims.Txn {
				t.Errorf("forwarded sub=%q token_use=%q txn=%q, want %q %q %q",
					claims.Subject, claims.TokenUse, claims.Txn, observation, internaljwt.TokenUseService, presented.Claims.Txn)
			}

			assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
				"method":         graphv1connect.GraphSupplyServiceGetObservationPointMappingsProcedure,
				"result":         "ok",
				"caller_service": observation,
				"origin":         test.wantOrigin,
			})
		})
	}
}

func TestInternalListenerRejects(t *testing.T) {
	t.Parallel()

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	foreign, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    gatewayIssuerID,
		Audience:  jwt.ClaimStrings{graphAuthoring},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}).SignedString(foreignKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v, want nil", err)
	}

	idpURL := startFakeIDP(t)

	tests := map[string]struct {
		call       func(t *testing.T, f serviceFixture, header map[string]string) error
		header     func(t *testing.T, f serviceFixture) map[string]string
		wantCode   connectrpc.Code
		wantReason string
		wantCaller any
	}{
		"both a context token and a declared caller": {
			call: getEvent,
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				header := bearerHeader(f.eventAccessFor(t, graphAuthoring).Token)
				header["Tolo-Caller-Service"] = graphAuthoring

				return header
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "ambiguous_service_credential",
		},
		"neither a context token nor a declared caller": {
			call:       getEvent,
			header:     func(*testing.T, serviceFixture) map[string]string { return nil },
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "missing_service_credential",
		},
		"an empty declared caller": {
			call: getEvent,
			header: func(*testing.T, serviceFixture) map[string]string {
				return map[string]string{"Tolo-Caller-Service": ""}
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "malformed_caller_service",
		},
		"an authorization that is not a bearer token": {
			call: getEvent,
			header: func(*testing.T, serviceFixture) map[string]string {
				return map[string]string{"Authorization": "Basic abc"}
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "malformed_authorization",
		},
		"a bearer token that is not a JWT": {
			call:       getEvent,
			header:     func(*testing.T, serviceFixture) map[string]string { return bearerHeader("not-a-jwt") },
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "invalid_context",
		},
		"a DPoP proof": {
			call: getEvent,
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				header := bearerHeader(f.eventAccessFor(t, graphAuthoring).Token)
				header["DPoP"] = "proof"

				return header
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "dpop_unsupported",
		},
		"a context token the gateway did not sign": {
			call:       getEvent,
			header:     func(*testing.T, serviceFixture) map[string]string { return bearerHeader(foreign) },
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "invalid_context",
		},
		"an external IdP token": {
			call: getEvent,
			header: func(t *testing.T, _ serviceFixture) map[string]string {
				t.Helper()

				return bearerHeader(issueExternalToken(t, idpURL, externalTokenRequest(contextScope, externalTenantID)))
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "invalid_context",
		},
		"a declared caller on an edge that needs a context": {
			call: getEvent,
			header: func(*testing.T, serviceFixture) map[string]string {
				return map[string]string{"Tolo-Caller-Service": graphAuthoring}
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "context_required",
			wantCaller: graphAuthoring,
		},
		"a declared caller with no edge": {
			call: getEvent,
			header: func(*testing.T, serviceFixture) map[string]string {
				return map[string]string{"Tolo-Caller-Service": "tolo-unknown"}
			},
			wantCode:   connectrpc.CodePermissionDenied,
			wantReason: "edge_not_allowed",
			wantCaller: "tolo-unknown",
		},
		"a graph authoring context on the observation edge": {
			call: getObservationPointMappings,
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				return bearerHeader(f.eventAccessFor(t, graphAuthoring).Token)
			},
			wantCode:   connectrpc.CodePermissionDenied,
			wantReason: "edge_not_allowed",
			wantCaller: graphAuthoring,
		},
		"a machine-origin chain on an edge that does not accept one": {
			call: getEvent,
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				return bearerHeader(f.machineOriginFor(t, graphAuthoring).Token)
			},
			wantCode:   connectrpc.CodePermissionDenied,
			wantReason: "edge_not_allowed",
			wantCaller: graphAuthoring,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newServiceGateway(t, config.InboundInternal)

			err := test.call(t, f, test.header(t, f))

			if got := gatewayError(t, err).Code(); got != test.wantCode {
				t.Errorf("code = %v, want %v", got, test.wantCode)
			}

			f.assertNotForwarded(t)

			record := singleAuditRecord(t, f.audit)

			assertAudit(t, record, map[string]any{
				"result":         test.wantCode.String(),
				"failure_reason": test.wantReason,
				"caller_service": test.wantCaller,
			})

			if _, ok := record["jti"]; ok {
				t.Errorf("audit.jti = %v, want none", record["jti"])
			}
		})
	}
}

func TestPublicListenerExecutesNoServiceCall(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		header     func(t *testing.T, f serviceFixture) map[string]string
		wantCode   connectrpc.Code
		wantReason string
	}{
		"an external token": {
			header:     func(*testing.T, serviceFixture) map[string]string { return bearerHeader(acceptedToken) },
			wantCode:   connectrpc.CodePermissionDenied,
			wantReason: "internal_only",
		},
		"a context token": {
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				return bearerHeader(f.eventAccessFor(t, graphAuthoring).Token)
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "invalid_token",
		},
		"a declared caller": {
			header: func(*testing.T, serviceFixture) map[string]string {
				return map[string]string{"Tolo-Caller-Service": graphAuthoring}
			},
			wantCode:   connectrpc.CodeUnauthenticated,
			wantReason: "caller_service_on_public",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newServiceGateway(t, config.InboundPublic)

			err := getEvent(t, f, test.header(t, f))

			if got := gatewayError(t, err).Code(); got != test.wantCode {
				t.Errorf("code = %v, want %v", got, test.wantCode)
			}

			f.assertNotForwarded(t)

			assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
				"method":         tenantv1connect.TenantServiceGetEventProcedure,
				"result":         test.wantCode.String(),
				"failure_reason": test.wantReason,
			})
		})
	}
}

func TestPublicListenerExchangesAStaffTokenForOperation(t *testing.T) {
	t.Parallel()

	f := newServiceGateway(t, config.InboundPublic)

	if err := listStaffMessages(t, f, bearerHeader(staffToken)); err != nil {
		t.Fatalf("ListStaffMessages() error = %v, want nil", err)
	}

	_, claims := f.forwarded(t, operation)

	if claims.TokenUse != internaljwt.TokenUseEventAccess || claims.Subject != externalSubject || claims.EventPublicID != contextEventID {
		t.Errorf("forwarded token_use=%q sub=%q event_id=%q, want %q %q %q",
			claims.TokenUse, claims.Subject, claims.EventPublicID, internaljwt.TokenUseEventAccess, externalSubject, contextEventID)
	}

	assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
		"method": operationv1connect.StaffCommunicationServiceListStaffMessagesProcedure,
		"result": "ok",
	})
}

func TestPublicListenerKeepsProposalDeliveryInternal(t *testing.T) {
	t.Parallel()

	f := newServiceGateway(t, config.InboundPublic)

	err := requestProposalDelivery(t, f, bearerHeader(staffToken))

	if got := gatewayError(t, err).Code(); got != connectrpc.CodePermissionDenied {
		t.Errorf("code = %v, want %v", got, connectrpc.CodePermissionDenied)
	}

	f.assertNotForwarded(t)

	assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
		"method":         operationv1connect.DeliveryCoordinationServiceRequestProposalDeliveryProcedure,
		"result":         connectrpc.CodePermissionDenied.String(),
		"failure_reason": "internal_only",
	})
}

func TestInternalListenerReissuesOperationCalls(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		call       func(t *testing.T, f serviceFixture, header map[string]string) error
		header     func(t *testing.T, f serviceFixture) map[string]string
		caller     string
		method     string
		wantOrigin string
	}{
		"a proposal delivery in an observation event context": {
			call: requestProposalDelivery,
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				return bearerHeader(f.eventAccessFor(t, observation).Token)
			},
			caller:     observation,
			method:     operationv1connect.DeliveryCoordinationServiceRequestProposalDeliveryProcedure,
			wantOrigin: "user",
		},
		"a proposal delivery in an observation machine-origin chain": {
			call: requestProposalDelivery,
			header: func(t *testing.T, f serviceFixture) map[string]string {
				t.Helper()

				return bearerHeader(f.machineOriginFor(t, observation).Token)
			},
			caller:     observation,
			method:     operationv1connect.DeliveryCoordinationServiceRequestProposalDeliveryProcedure,
			wantOrigin: "machine_chain",
		},
		"a staff message pull the guest service starts": {
			call: listStaffMessages,
			header: func(*testing.T, serviceFixture) map[string]string {
				return map[string]string{"Tolo-Caller-Service": guest}
			},
			caller:     guest,
			method:     operationv1connect.StaffCommunicationServiceListStaffMessagesProcedure,
			wantOrigin: "new_machine",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newServiceGateway(t, config.InboundInternal)

			if err := test.call(t, f, test.header(t, f)); err != nil {
				t.Fatalf("call error = %v, want nil", err)
			}

			_, claims := f.forwarded(t, operation)

			if claims.Subject != test.caller || claims.TokenUse != internaljwt.TokenUseService {
				t.Errorf("forwarded sub=%q token_use=%q, want %q %q", claims.Subject, claims.TokenUse, test.caller, internaljwt.TokenUseService)
			}

			assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
				"method":         test.method,
				"result":         "ok",
				"caller_service": test.caller,
				"origin":         test.wantOrigin,
			})
		})
	}
}

func TestInternalListenerReissuesGuestMachineOriginCalls(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		call        func(t *testing.T, f serviceFixture, header map[string]string) error
		method      string
		destination string
	}{
		"a display name pull": {
			call:        getDisplayNames,
			method:      graphv1connect.GraphSupplyServiceGetDisplayNamesProcedure,
			destination: graphAuthoring,
		},
		"a QR location pull": {
			call:        getQrLocations,
			method:      graphv1connect.GraphSupplyServiceGetQrLocationsProcedure,
			destination: graphAuthoring,
		},
		"a guest snapshot pull": {
			call:        getGuestSnapshot,
			method:      observationv1connect.StatusQueryServiceGetGuestSnapshotProcedure,
			destination: observation,
		},
		"a QR scan report": {
			call:        reportMeasurements,
			method:      observationv1connect.MeasurementIngestServiceReportMeasurementsProcedure,
			destination: observation,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newServiceGateway(t, config.InboundInternal)

			if err := test.call(t, f, map[string]string{"Tolo-Caller-Service": guest}); err != nil {
				t.Fatalf("call error = %v, want nil", err)
			}

			_, claims := f.forwarded(t, test.destination)

			if claims.Subject != guest || claims.TokenUse != internaljwt.TokenUseService || claims.Scope != "" {
				t.Errorf("forwarded sub=%q token_use=%q scope=%q, want %q %q and no scope",
					claims.Subject, claims.TokenUse, claims.Scope, guest, internaljwt.TokenUseService)
			}

			assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
				"method":         test.method,
				"result":         "ok",
				"caller_service": guest,
				"origin":         "new_machine",
			})
		})
	}
}

func TestPublicListenerForwardsAnAnonymousGuestPageWithoutAuthorization(t *testing.T) {
	t.Parallel()

	f := newServiceGateway(t, config.InboundPublic)

	_, err := f.guestPages.OpenGuestPage(t.Context(), &guestv1.OpenGuestPageRequest{EventId: contextEventID})
	if err != nil {
		t.Fatalf("OpenGuestPage() error = %v, want nil", err)
	}

	var forwarded http.Header

	select {
	case forwarded = <-f.upstream:
	default:
		t.Fatal("the upstream was not called")
	}

	if got := forwarded.Values("Authorization"); len(got) != 0 {
		t.Errorf("forwarded Authorization = %q, want none", got)
	}

	assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
		"method": guestv1connect.GuestPageServiceOpenGuestPageProcedure,
		"result": "ok",
	})
}

func TestPublicListenerExchangesAStaffTokenForGuestSettings(t *testing.T) {
	t.Parallel()

	f := newServiceGateway(t, config.InboundPublic)

	ctx, info := connectrpc.NewClientContext(t.Context())
	info.RequestHeader().Set("Authorization", "Bearer "+staffToken)

	if _, err := f.guestSettings.GetGuestSettings(ctx, &guestv1.GetGuestSettingsRequest{EventId: contextEventID}); err != nil {
		t.Fatalf("GetGuestSettings() error = %v, want nil", err)
	}

	_, claims := f.forwarded(t, guest)

	if claims.TokenUse != internaljwt.TokenUseEventAccess || claims.Subject != externalSubject || claims.EventPublicID != contextEventID {
		t.Errorf("forwarded token_use=%q sub=%q event_id=%q, want %q %q %q",
			claims.TokenUse, claims.Subject, claims.EventPublicID, internaljwt.TokenUseEventAccess, externalSubject, contextEventID)
	}

	assertAudit(t, singleAuditRecord(t, f.audit), map[string]any{
		"method": guestv1connect.GuestSettingsServiceGetGuestSettingsProcedure,
		"result": "ok",
	})
}
