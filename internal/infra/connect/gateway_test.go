package connect_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/pj-hoakari/internal-jwt-handling/issuer"
	"github.com/pj-hoakari/internal-jwt-handling/jwks"
	"github.com/pj-hoakari/internal-jwt-handling/verifier"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/protobuf/reflect/protoregistry"

	greetv1 "github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1"
	"github.com/pj-hoakari/tolo-service-gateway/gen/greet/v1/greetv1connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/fakeidp"
	"github.com/pj-hoakari/tolo-service-gateway/internal/idp"
	infraconnect "github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/authn"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forward"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forwardgen"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
	"github.com/pj-hoakari/tolo-service-gateway/internal/logging"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
	"github.com/pj-hoakari/tolo-service-gateway/internal/testbackend"
)

const (
	gatewayIssuerID     = "service-gateway"
	gatewaySigningKeyID = "dev-key-1"
	backendAudience     = "tolo-testbackend"
	externalAudience    = "backend-api"

	introspectionClientID   = "gateway-introspection"
	introspectionCredential = "introspection-client-credential"
)

type upstreamCall struct {
	remaining time.Duration
	header    http.Header
}

type upstreamGreetService struct {
	greetv1connect.UnimplementedGreetServiceHandler
	records chan upstreamCall
}

func (s upstreamGreetService) record(ctx context.Context, req connectrpc.AnyRequest) {
	remaining := time.Duration(0)

	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}

	s.records <- upstreamCall{remaining: remaining, header: req.Header().Clone()}
}

func (s upstreamGreetService) Ping(ctx context.Context, req *connectrpc.Request[greetv1.PingRequest]) (*connectrpc.Response[greetv1.PingResponse], error) {
	s.record(ctx, req)

	return connectrpc.NewResponse(&greetv1.PingResponse{Message: "pong"}), nil
}

func (s upstreamGreetService) Greet(ctx context.Context, req *connectrpc.Request[greetv1.GreetRequest]) (*connectrpc.Response[greetv1.GreetResponse], error) {
	s.record(ctx, req)

	return connectrpc.NewResponse(&greetv1.GreetResponse{Greeting: "Hello!"}), nil
}

type gatewayFixture struct {
	client     greetv1connect.GreetServiceClient
	gatewayURL string
	upstream   *httptest.Server
	records    chan upstreamCall
	audit      *bytes.Buffer
}

func newGateway(t *testing.T) gatewayFixture {
	t.Helper()

	records := make(chan upstreamCall, 8)

	mux := http.NewServeMux()
	path, handler := greetv1connect.NewGreetServiceHandler(upstreamGreetService{
		UnimplementedGreetServiceHandler: greetv1connect.UnimplementedGreetServiceHandler{},
		records:                          records,
	})
	mux.Handle(path, handler)

	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	provider := sdktrace.NewTracerProvider()

	tracing, err := otelconnect.NewInterceptor(
		otelconnect.WithTracerProvider(provider),
		otelconnect.WithPropagator(propagation.TraceContext{}),
	)
	if err != nil {
		t.Fatalf("NewInterceptor() error = %v, want nil", err)
	}

	handlers, err := forward.Handlers(
		catalog.Bindings(),
		destinationsTo(t, upstream.URL),
		forwardgen.Mounts(),
		forward.NewHTTPClient(http.DefaultTransport),
		[]connectrpc.ClientOption{connectrpc.WithInterceptors(tracing)},
		[]connectrpc.HandlerOption{connectrpc.WithInterceptors(infraconnect.AuditInterceptor())},
	)
	if err != nil {
		t.Fatalf("Handlers() error = %v, want nil", err)
	}

	logs := &bytes.Buffer{}

	gateway := httptest.NewServer(httpapi.NewHandler(infraconnect.Routes(infraconnect.Config{
		Registry: built,
		Handlers: handlers,
		Audit: audit.NewEmitter(logging.NewLogger(logs, logging.Options{
			Level:     slog.LevelInfo,
			AddSource: false,
			ProjectID: "",
		})),
		TracerProvider:   provider,
		TrustedProxyHops: 0,
	})))
	t.Cleanup(gateway.Close)

	return gatewayFixture{
		client:     greetv1connect.NewGreetServiceClient(gateway.Client(), gateway.URL),
		gatewayURL: gateway.URL,
		upstream:   upstream,
		records:    records,
		audit:      logs,
	}
}

func destinationsTo(t *testing.T, rawURL string) registry.Destinations {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", rawURL, err)
	}

	destinations := make(registry.Destinations)
	for _, binding := range catalog.Bindings() {
		destinations[binding.Destination] = registry.Destination{URL: parsed}
	}

	return destinations
}

func gatewayError(t *testing.T, err error) *connectrpc.Error {
	t.Helper()

	if err == nil {
		t.Fatal("the call succeeded, want an error")
	}

	var got *connectrpc.Error
	if !errors.As(err, &got) {
		t.Fatalf("error = %v, want a *connect.Error", err)
	}

	return got
}

func TestGatewayForwardsAnonymousProcedures(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	res, err := fixture.client.Ping(t.Context(), connectrpc.NewRequest(&greetv1.PingRequest{}))
	if err != nil {
		t.Fatalf("Ping() error = %v, want nil", err)
	}

	if got, want := res.Msg.GetMessage(), "pong"; got != want {
		t.Errorf("message = %q, want %q", got, want)
	}

	if got := len(fixture.records); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}

	assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{
		"method":      anonymousProcedure,
		"result":      "ok",
		"http_status": float64(http.StatusOK),
	})
}

func TestGatewayStopsAuthenticatedProceduresBeforeTheUpstream(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	_, err := fixture.client.Greet(t.Context(), connectrpc.NewRequest(&greetv1.GreetRequest{Name: "tolo"}))

	if got, want := gatewayError(t, err).Code(), connectrpc.CodeUnauthenticated; got != want {
		t.Errorf("code = %v, want %v", got, want)
	}

	if got := len(fixture.records); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}

func TestGatewayCarriesTheClientDeadlineToTheUpstream(t *testing.T) {
	t.Parallel()

	const timeout = 3 * time.Second

	fixture := newGateway(t)

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	if _, err := fixture.client.Ping(ctx, connectrpc.NewRequest(&greetv1.PingRequest{})); err != nil {
		t.Fatalf("Ping() error = %v, want nil", err)
	}

	remaining := (<-fixture.records).remaining

	if remaining <= 0 || remaining > timeout {
		t.Errorf("the upstream deadline leaves %v, want more than 0 and at most %v", remaining, timeout)
	}
}

func TestGatewayAnswersAnUnreachableUpstreamWithUnavailable(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)
	fixture.upstream.Close()

	_, err := fixture.client.Ping(t.Context(), connectrpc.NewRequest(&greetv1.PingRequest{}))

	got := gatewayError(t, err)

	if got.Code() != connectrpc.CodeUnavailable {
		t.Errorf("code = %v, want %v", got.Code(), connectrpc.CodeUnavailable)
	}

	if got.Message() != "upstream unavailable" {
		t.Errorf("message = %q, want %q", got.Message(), "upstream unavailable")
	}

	assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{
		"method":         anonymousProcedure,
		"result":         "unavailable",
		"failure_reason": "upstream_unreachable",
	})
}

func TestGatewayAnswersUnregisteredProceduresWithUnimplemented(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fixture.gatewayURL+absentProcedure, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, http.StatusNotImplemented; got != want {
		t.Errorf("status = %d, want %d", got, want)
	}

	if got := len(fixture.records); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}

	if got := auditRecords(t, fixture.audit); len(got) != 0 {
		t.Errorf("audit records = %v, want none", got)
	}
}

func TestGatewayGivesTheUpstreamItsOwnTraceContext(t *testing.T) {
	t.Parallel()

	fixture := newGateway(t)

	req := connectrpc.NewRequest(&greetv1.PingRequest{})
	req.Header().Set("Traceparent", clientTraceparent)

	res, err := fixture.client.Ping(t.Context(), req)
	if err != nil {
		t.Fatalf("Ping() error = %v, want nil", err)
	}

	assertNoCorrelationHeaders(t, res.Header())

	call := <-fixture.records

	if _, forwarded := call.header[http.CanonicalHeaderKey("X-Request-Id")]; forwarded {
		t.Errorf("the upstream saw X-Request-Id, want it withheld")
	}

	traceparent := call.header.Get("Traceparent")
	if traceparent == "" {
		t.Fatalf("upstream headers = %v, want a traceparent", call.header)
	}

	upstreamTraceID := traceIDOf(t, traceparent)

	if upstreamTraceID == clientTraceID {
		t.Errorf("upstream trace ID = %q, want it not to follow the trace context of the client", upstreamTraceID)
	}

	record := singleAuditRecord(t, fixture.audit)

	assertCorrelated(t, record)

	if got := record["trace_id"]; got != upstreamTraceID {
		t.Errorf("audit.trace_id = %v, want the trace ID the upstream saw (%q)", got, upstreamTraceID)
	}
}

type gatewayKeyProvider struct {
	keys issuer.KeySet
}

func (p gatewayKeyProvider) Current(context.Context) (issuer.KeySet, error) {
	return p.keys, nil
}

type authorizationRecorder struct {
	next    http.Handler
	headers chan string
}

func (a authorizationRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.headers <- r.Header.Get("Authorization")

	a.next.ServeHTTP(w, r)
}

type verifyingFixture struct {
	client  greetv1connect.GreetServiceClient
	headers chan string
	audit   *bytes.Buffer
}

func newGatewayIssuer(t *testing.T) *issuer.Issuer {
	t.Helper()

	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}

	gatewayIssuer, err := issuer.New(gatewayIssuerID, gatewayKeyProvider{
		keys: issuer.KeySet{
			Signing:   issuer.SigningKey{KeyID: gatewaySigningKeyID, Key: signing},
			Published: nil,
		},
	})
	if err != nil {
		t.Fatalf("issuer.New() error = %v, want nil", err)
	}

	return gatewayIssuer
}

func newVerifyingBackend(t *testing.T, gatewayIssuer *issuer.Issuer) (string, chan string) {
	t.Helper()

	jwksServer := httptest.NewServer(httpapi.NewHandler(httpapi.PublicRoutes(httpapi.NewJWKSHandler(gatewayIssuer))))
	t.Cleanup(jwksServer.Close)

	cache, err := jwks.New(jwks.Config{
		URL:             jwksServer.URL + httpapi.JWKSPath,
		HTTPClient:      nil,
		CacheTTL:        0,
		RefreshCooldown: 0,
		FailureCooldown: 0,
		FetchTimeout:    2 * time.Second,
		RetryBackoff:    []time.Duration{},
		MaxDocumentSize: 0,
	})
	if err != nil {
		t.Fatalf("jwks.New() error = %v, want nil", err)
	}

	tokenVerifier, err := verifier.New(gatewayIssuerID, backendAudience, cache)
	if err != nil {
		t.Fatalf("verifier.New() error = %v, want nil", err)
	}

	handler, err := testbackend.NewHandler(tokenVerifier)
	if err != nil {
		t.Fatalf("NewHandler() error = %v, want nil", err)
	}

	headers := make(chan string, 8)

	backend := httptest.NewServer(authorizationRecorder{next: handler, headers: headers})
	t.Cleanup(backend.Close)

	return backend.URL, headers
}

func newVerifyingGateway(t *testing.T) verifyingFixture {
	t.Helper()

	return newVerifyingGatewayWith(t, newAuthenticator(), newRegistry(t))
}

func newVerifyingGatewayWith(t *testing.T, authenticator *authn.Authenticator, built *registry.Registry) verifyingFixture {
	t.Helper()

	gatewayIssuer := newGatewayIssuer(t)
	backendURL, headers := newVerifyingBackend(t, gatewayIssuer)

	handlers, err := forward.Handlers(
		catalog.Bindings(),
		destinationsTo(t, backendURL),
		forwardgen.Mounts(),
		forward.NewHTTPClient(http.DefaultTransport),
		[]connectrpc.ClientOption{connectrpc.WithInterceptors(forward.AuthorizationInterceptor())},
		[]connectrpc.HandlerOption{connectrpc.WithInterceptors(infraconnect.AuditInterceptor())},
	)
	if err != nil {
		t.Fatalf("Handlers() error = %v, want nil", err)
	}

	logs := &bytes.Buffer{}

	gateway := httptest.NewServer(httpapi.NewHandler(infraconnect.Routes(infraconnect.Config{
		Registry: built,
		Handlers: handlers,
		Audit: audit.NewEmitter(logging.NewLogger(logs, logging.Options{
			Level:     slog.LevelInfo,
			AddSource: false,
			ProjectID: "",
		})),
		Authenticator:    authenticator,
		Issuer:           gatewayIssuer,
		TracerProvider:   sdktrace.NewTracerProvider(),
		TrustedProxyHops: 0,
	})))
	t.Cleanup(gateway.Close)

	return verifyingFixture{
		client:  greetv1connect.NewGreetServiceClient(gateway.Client(), gateway.URL),
		headers: headers,
		audit:   logs,
	}
}

func greetWith(t *testing.T, fixture verifyingFixture, token string) (*connectrpc.Response[greetv1.GreetResponse], error) {
	t.Helper()

	req := connectrpc.NewRequest(&greetv1.GreetRequest{Name: "tolo"})
	req.Header().Set("Authorization", "Bearer "+token)

	return fixture.client.Greet(t.Context(), req) //nolint:wrapcheck // the test asserts on the error the gateway returns
}

func TestGatewayExchangesAnExternalTokenTheUpstreamAccepts(t *testing.T) {
	t.Parallel()

	fixture := newVerifyingGateway(t)

	res, err := greetWith(t, fixture, acceptedToken)
	if err != nil {
		t.Fatalf("Greet() error = %v, want nil", err)
	}

	if got, want := res.Msg.GetGreeting(), "Hello, tolo!"; got != want {
		t.Errorf("greeting = %q, want %q", got, want)
	}

	authorization := <-fixture.headers

	if authorization == "Bearer "+acceptedToken {
		t.Error("the upstream saw the external token, want the internal JWT instead")
	}

	if !strings.HasPrefix(authorization, "Bearer ") {
		t.Errorf("upstream Authorization = %q, want a bearer token", authorization)
	}

	record := singleAuditRecord(t, fixture.audit)

	assertAudit(t, record, map[string]any{
		"method":    authenticatedProcedure,
		"result":    "ok",
		"client_id": externalClientID,
		"sub":       externalSubject,
		"src_jti":   externalJTI,
	})

	if got, want := record["jti"], strings.TrimPrefix(authorization, "Bearer "); got == want {
		t.Errorf("audit.jti = %v, want the jti of the internal JWT, not the token itself", got)
	}
}

func TestGatewayStopsAnExternalTokenWithoutTheRequiredScope(t *testing.T) {
	t.Parallel()

	fixture := newVerifyingGateway(t)

	_, err := greetWith(t, fixture, scopelessToken)

	if got, want := gatewayError(t, err).Code(), connectrpc.CodePermissionDenied; got != want {
		t.Errorf("code = %v, want %v", got, want)
	}

	if got := len(fixture.headers); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}

	assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{
		"method":         authenticatedProcedure,
		"result":         "permission_denied",
		"failure_reason": "missing_scope",
	})
}

func startFakeIDPWith(t *testing.T, clientID, secret string) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)

	handler, err := fakeidp.NewHandler(fakeidp.Config{
		Issuer:                    "http://" + server.Listener.Addr().String(),
		Audience:                  externalAudience,
		IntrospectionClientID:     clientID,
		IntrospectionClientSecret: secret,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v, want nil", err)
	}

	server.Config.Handler = handler
	server.Start()

	return server
}

func startFakeIDP(t *testing.T) string {
	t.Helper()

	return startFakeIDPWith(t, "", "").URL
}

func newIDPGateway(t *testing.T) (verifyingFixture, string) {
	t.Helper()

	issuer := startFakeIDP(t)

	provider, err := idp.New(idp.Config{
		Issuer:     issuer,
		Audience:   externalAudience,
		Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatalf("idp.New() error = %v, want nil", err)
	}

	if err := provider.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	return newVerifyingGatewayWith(t, authn.NewAuthenticator(provider, nil), newRegistry(t)), issuer
}

func introspectingRegistry(t *testing.T) *registry.Registry {
	t.Helper()

	built, err := registry.Build(
		catalog.Bindings(),
		registry.Overrides{Introspection: []string{greetv1connect.GreetServiceGreetProcedure}},
		protoregistry.GlobalFiles,
	)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	return built
}

func newIntrospectingGateway(t *testing.T) (verifyingFixture, *httptest.Server) {
	t.Helper()

	idpServer := startFakeIDPWith(t, introspectionClientID, introspectionCredential)

	provider, err := idp.New(idp.Config{
		Issuer:                    idpServer.URL,
		Audience:                  externalAudience,
		Algorithms:                []string{"RS256"},
		IntrospectionClientID:     introspectionClientID,
		IntrospectionClientSecret: introspectionCredential,
	})
	if err != nil {
		t.Fatalf("idp.New() error = %v, want nil", err)
	}

	if err := provider.Run(t.Context()); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	fixture := newVerifyingGatewayWith(t, authn.NewAuthenticator(provider, provider), introspectingRegistry(t))

	return fixture, idpServer
}

func revokeExternalToken(t *testing.T, issuer, token string) {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{"token": token})
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+fakeidp.RevokePath, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d", fakeidp.RevokePath, res.StatusCode, http.StatusOK)
	}
}

func TestGatewayForwardsAnIntrospectionBoundRPCWhileTheTokenIsActive(t *testing.T) {
	t.Parallel()

	fixture, idpServer := newIntrospectingGateway(t)

	token := issueExternalToken(t, idpServer.URL, externalTokenRequest(greetScope, externalTenantID))

	if _, err := greetWith(t, fixture, token); err != nil {
		t.Fatalf("Greet() error = %v, want nil", err)
	}

	if got := len(fixture.headers); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}

	assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{
		"method": authenticatedProcedure,
		"result": "ok",
	})
}

func TestGatewayStopsAnIntrospectionBoundRPCOnceTheTokenIsRevoked(t *testing.T) {
	t.Parallel()

	fixture, idpServer := newIntrospectingGateway(t)

	token := issueExternalToken(t, idpServer.URL, externalTokenRequest(greetScope, externalTenantID))

	revokeExternalToken(t, idpServer.URL, token)

	_, err := greetWith(t, fixture, token)

	if got, want := gatewayError(t, err).Code(), connectrpc.CodeUnauthenticated; got != want {
		t.Errorf("code = %v, want %v", got, want)
	}

	if got := len(fixture.headers); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}

	assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{
		"method":         authenticatedProcedure,
		"result":         "unauthenticated",
		"failure_reason": authn.ReasonTokenRevoked,
	})
}

func TestGatewayStopsAnIntrospectionBoundRPCWhenTheIDPCannotBeAsked(t *testing.T) {
	t.Parallel()

	fixture, idpServer := newIntrospectingGateway(t)

	warm := issueExternalToken(t, idpServer.URL, externalTokenRequest(greetScope, externalTenantID))
	token := issueExternalToken(t, idpServer.URL, externalTokenRequest(greetScope, externalTenantID))

	if _, err := greetWith(t, fixture, warm); err != nil {
		t.Fatalf("Greet() error = %v, want nil", err)
	}

	idpServer.Close()

	_, err := greetWith(t, fixture, token)

	if got, want := gatewayError(t, err).Code(), connectrpc.CodeUnauthenticated; got != want {
		t.Errorf("code = %v, want %v", got, want)
	}

	records := auditRecords(t, fixture.audit)
	if len(records) != 2 {
		t.Fatalf("audit records = %d, want 2", len(records))
	}

	assertAudit(t, records[1], map[string]any{
		"method":         authenticatedProcedure,
		"result":         "unauthenticated",
		"failure_reason": authn.ReasonIntrospectionUnavailable,
	})
}

func issueExternalToken(t *testing.T, issuer string, request map[string]any) string {
	t.Helper()

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+fakeidp.TokenPath, bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v, want nil", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, want %d", fakeidp.TokenPath, res.StatusCode, http.StatusOK)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v, want nil", err)
	}

	return body.AccessToken
}

func externalTokenRequest(scope, tenantID string) map[string]any {
	return map[string]any{
		"token_use":   "tenant_access",
		"sub":         externalSubject,
		"client_id":   externalClientID,
		"scope":       scope,
		"tenant_id":   tenantID,
		"ttl_seconds": 300,
	}
}

func TestGatewayForwardsACallAuthenticatedByTheIDP(t *testing.T) {
	t.Parallel()

	fixture, issuer := newIDPGateway(t)

	token := issueExternalToken(t, issuer, externalTokenRequest(greetScope, externalTenantID))

	res, err := greetWith(t, fixture, token)
	if err != nil {
		t.Fatalf("Greet() error = %v, want nil", err)
	}

	if got, want := res.Msg.GetGreeting(), "Hello, tolo!"; got != want {
		t.Errorf("greeting = %q, want %q", got, want)
	}

	authorization := <-fixture.headers

	if !strings.HasPrefix(authorization, "Bearer ") || strings.Contains(authorization, token) {
		t.Errorf("upstream Authorization = %q, want the internal JWT instead of the external token", authorization)
	}

	assertAudit(t, singleAuditRecord(t, fixture.audit), map[string]any{
		"method":    authenticatedProcedure,
		"result":    "ok",
		"client_id": externalClientID,
		"sub":       externalSubject,
	})
}

func TestGatewayStopsTokensTheIDPIssuedOutsideTheSpecifiedShape(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		request map[string]any
		want    connectrpc.Code
	}{
		"a token without the required scope": {
			request: externalTokenRequest("other.read", externalTenantID),
			want:    connectrpc.CodePermissionDenied,
		},
		"a tenant ID that is not a public ID": {
			request: externalTokenRequest(greetScope, "tenant-a"),
			want:    connectrpc.CodeUnauthenticated,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixture, issuer := newIDPGateway(t)

			_, err := greetWith(t, fixture, issueExternalToken(t, issuer, test.request))

			if got := gatewayError(t, err).Code(); got != test.want {
				t.Errorf("code = %v, want %v", got, test.want)
			}

			if got := len(fixture.headers); got != 0 {
				t.Errorf("upstream calls = %d, want 0", got)
			}
		})
	}
}

func traceIDOf(t *testing.T, traceparent string) string {
	t.Helper()

	fields := strings.Split(traceparent, "-")
	if len(fields) != 4 {
		t.Fatalf("traceparent = %q, want four fields", traceparent)
	}

	return fields[1]
}
