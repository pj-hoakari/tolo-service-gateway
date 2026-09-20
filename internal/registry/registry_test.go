package registry_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/protoc-gen-authz-go/authz"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	testService     = "test.v1.Service"
	testProcedure   = "/test.v1.Service/Method"
	testDestination = "tolo-testbackend"
	testMessage     = "test.v1.Empty"
)

type methodSpec struct {
	name            string
	streamingClient bool
	streamingServer bool
}

type serviceSpec struct {
	name    string
	methods []methodSpec
}

func newResolver(t *testing.T, services ...serviceSpec) *protoregistry.Files {
	t.Helper()

	file := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("test/v1/test.proto"),
		Package:     proto.String("test.v1"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Empty")}},
	}

	for _, service := range services {
		descriptor := &descriptorpb.ServiceDescriptorProto{Name: proto.String(service.name)}

		for _, method := range service.methods {
			descriptor.Method = append(descriptor.Method, &descriptorpb.MethodDescriptorProto{
				Name:            proto.String(method.name),
				InputType:       proto.String("." + testMessage),
				OutputType:      proto.String("." + testMessage),
				ClientStreaming: proto.Bool(method.streamingClient),
				ServerStreaming: proto.Bool(method.streamingServer),
			})
		}

		file.Service = append(file.Service, descriptor)
	}

	descriptor, err := protodesc.NewFile(file, nil)
	if err != nil {
		t.Fatalf("build the test file descriptor: %v", err)
	}

	files := new(protoregistry.Files)
	if err := files.RegisterFile(descriptor); err != nil {
		t.Fatalf("register the test file descriptor: %v", err)
	}

	return files
}

func singleMethodResolver(t *testing.T) *protoregistry.Files {
	t.Helper()

	return newResolver(t, serviceSpec{name: "Service", methods: []methodSpec{{name: "Method"}}})
}

func binding(policy authz.Policy) []registry.Binding {
	return []registry.Binding{{
		Service:     testService,
		Destination: testDestination,
		Policies:    authz.Policies{testProcedure: policy},
	}}
}

func TestBuildDerivesEntries(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		policy authz.Policy
		want   registry.Entry
	}{
		"public accepts anonymous callers": {
			policy: authz.Policy{Level: authz.LevelPublic},
			want: registry.Entry{
				Procedure:         testProcedure,
				Destination:       testDestination,
				Anonymous:         true,
				ExternalTokenUses: nil,
				Service:           false,
				RequiredScopes:    nil,
				Introspection:     false,
			},
		},
		"internal without token uses accepts the service subject": {
			policy: authz.Policy{Level: authz.LevelInternal},
			want: registry.Entry{
				Procedure:         testProcedure,
				Destination:       testDestination,
				Anonymous:         false,
				ExternalTokenUses: nil,
				Service:           true,
				RequiredScopes:    nil,
				Introspection:     false,
			},
		},
		"internal with the service token use accepts the service subject": {
			policy: authz.Policy{Level: authz.LevelInternal, TokenUses: []string{internaljwt.TokenUseService}},
			want: registry.Entry{
				Procedure:         testProcedure,
				Destination:       testDestination,
				Anonymous:         false,
				ExternalTokenUses: nil,
				Service:           true,
				RequiredScopes:    nil,
				Introspection:     false,
			},
		},
		"authenticated accepts the declared external token uses": {
			policy: authz.Policy{
				Level:          authz.LevelAuthenticated,
				RequiredScopes: []string{"greeting.read"},
				TokenUses:      []string{internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess},
			},
			want: registry.Entry{
				Procedure:         testProcedure,
				Destination:       testDestination,
				Anonymous:         false,
				ExternalTokenUses: []string{internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess},
				Service:           false,
				RequiredScopes:    []string{"greeting.read"},
				Introspection:     false,
			},
		},
		"authenticated with the service token use accepts both subjects": {
			policy: authz.Policy{
				Level:     authz.LevelAuthenticated,
				TokenUses: []string{internaljwt.TokenUseService, internaljwt.TokenUseRegistration},
			},
			want: registry.Entry{
				Procedure:         testProcedure,
				Destination:       testDestination,
				Anonymous:         false,
				ExternalTokenUses: []string{internaljwt.TokenUseRegistration},
				Service:           true,
				RequiredScopes:    nil,
				Introspection:     false,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			built, err := registry.Build(binding(tt.policy), registry.Overrides{}, singleMethodResolver(t))
			if err != nil {
				t.Fatalf("Build() error = %v, want nil", err)
			}

			got, ok := built.Lookup(testProcedure)
			if !ok {
				t.Fatalf("Lookup(%q) = _, false, want true", testProcedure)
			}

			assertEntry(t, got, tt.want)
		})
	}
}

func assertEntry(t *testing.T, got, want registry.Entry) {
	t.Helper()

	if got.Procedure != want.Procedure {
		t.Errorf("Procedure = %q, want %q", got.Procedure, want.Procedure)
	}

	if got.Destination != want.Destination {
		t.Errorf("Destination = %q, want %q", got.Destination, want.Destination)
	}

	if got.Anonymous != want.Anonymous {
		t.Errorf("Anonymous = %t, want %t", got.Anonymous, want.Anonymous)
	}

	if !slices.Equal(got.ExternalTokenUses, want.ExternalTokenUses) {
		t.Errorf("ExternalTokenUses = %v, want %v", got.ExternalTokenUses, want.ExternalTokenUses)
	}

	if got.Service != want.Service {
		t.Errorf("Service = %t, want %t", got.Service, want.Service)
	}

	if !slices.Equal(got.RequiredScopes, want.RequiredScopes) {
		t.Errorf("RequiredScopes = %v, want %v", got.RequiredScopes, want.RequiredScopes)
	}

	if got.Introspection != want.Introspection {
		t.Errorf("Introspection = %t, want %t", got.Introspection, want.Introspection)
	}
}

func TestBuildRejects(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bindings        []registry.Binding
		overrides       registry.Overrides
		services        []serviceSpec
		wantErrs        []error
		wantErrContains []string
	}{
		"a binding without a service": {
			bindings:        []registry.Binding{{Service: "", Destination: testDestination, Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidBinding},
			wantErrContains: []string{"binding 1"},
		},
		"a binding without a destination": {
			bindings:        []registry.Binding{{Service: testService, Destination: "", Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidBinding},
			wantErrContains: []string{testService, "destination"},
		},
		"a binding without policies": {
			bindings:        []registry.Binding{{Service: testService, Destination: testDestination, Policies: nil}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidBinding},
			wantErrContains: []string{testService, "policy"},
		},
		"the same service is bound twice": {
			bindings: []registry.Binding{
				{Service: testService, Destination: testDestination, Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}},
				{Service: testService, Destination: "other", Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}},
			},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidBinding},
			wantErrContains: []string{testService, "more than once"},
		},
		"two bindings claim the same procedure": {
			bindings: []registry.Binding{
				{Service: testService, Destination: testDestination, Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}},
				{Service: "test.v1.Other", Destination: "other", Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}},
			},
			services: []serviceSpec{
				{name: "Service", methods: []methodSpec{{name: "Method"}}},
				{name: "Other", methods: []methodSpec{{name: "Method"}}},
			},
			wantErrs:        []error{registry.ErrDuplicateProcedure},
			wantErrContains: []string{testProcedure},
		},
		"the service descriptor is unknown": {
			bindings:        binding(authz.Policy{Level: authz.LevelPublic}),
			services:        []serviceSpec{{name: "Other", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrServiceDescriptor},
			wantErrContains: []string{testService, "cannot be resolved"},
		},
		"the bound name is not a service": {
			bindings: []registry.Binding{{
				Service:     testMessage,
				Destination: testDestination,
				Policies:    authz.Policies{"/test.v1.Empty/Method": {Level: authz.LevelPublic}},
			}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrServiceDescriptor},
			wantErrContains: []string{testMessage, "not a service"},
		},
		"a declared method has no policy": {
			bindings: binding(authz.Policy{Level: authz.LevelPublic}),
			services: []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}, {name: "Other"}}}},
			wantErrs: []error{registry.ErrProcedureMismatch},
			wantErrContains: []string{
				"/test.v1.Service/Other",
				"has no policy",
			},
		},
		"a policy names a method the descriptor does not declare": {
			bindings: []registry.Binding{{
				Service:     testService,
				Destination: testDestination,
				Policies: authz.Policies{
					testProcedure:             {Level: authz.LevelPublic},
					"/test.v1.Service/Absent": {Level: authz.LevelPublic},
				},
			}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrProcedureMismatch},
			wantErrContains: []string{"/test.v1.Service/Absent", "not declared"},
		},
		"a client streaming method": {
			bindings:        binding(authz.Policy{Level: authz.LevelPublic}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method", streamingClient: true}}}},
			wantErrs:        []error{registry.ErrStreamingProcedure},
			wantErrContains: []string{testProcedure},
		},
		"a server streaming method": {
			bindings:        binding(authz.Policy{Level: authz.LevelPublic}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method", streamingServer: true}}}},
			wantErrs:        []error{registry.ErrStreamingProcedure},
			wantErrContains: []string{testProcedure},
		},
		"a public procedure declares token uses": {
			bindings:        binding(authz.Policy{Level: authz.LevelPublic, TokenUses: []string{internaljwt.TokenUseTenantAccess}}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "token uses"},
		},
		"a public procedure declares required scopes": {
			bindings:        binding(authz.Policy{Level: authz.LevelPublic, RequiredScopes: []string{"greeting.read"}}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "required scopes"},
		},
		"an internal procedure declares another token use": {
			bindings:        binding(authz.Policy{Level: authz.LevelInternal, TokenUses: []string{internaljwt.TokenUseTenantAccess}}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, internaljwt.TokenUseService},
		},
		"an internal procedure declares the service token use twice": {
			bindings: binding(authz.Policy{
				Level:     authz.LevelInternal,
				TokenUses: []string{internaljwt.TokenUseService, internaljwt.TokenUseService},
			}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure},
		},
		"an authenticated procedure declares no token use": {
			bindings:        binding(authz.Policy{Level: authz.LevelAuthenticated}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "no token use"},
		},
		"an authenticated procedure declares an unknown token use": {
			bindings:        binding(authz.Policy{Level: authz.LevelAuthenticated, TokenUses: []string{"guest_access"}}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "guest_access"},
		},
		"an authenticated procedure repeats a token use": {
			bindings: binding(authz.Policy{
				Level:     authz.LevelAuthenticated,
				TokenUses: []string{internaljwt.TokenUseTenantAccess, internaljwt.TokenUseTenantAccess},
			}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "more than once"},
		},
		"an authenticated procedure accepts only the service token use": {
			bindings:        binding(authz.Policy{Level: authz.LevelAuthenticated, TokenUses: []string{internaljwt.TokenUseService}}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "internal"},
		},
		"a procedure declares no access level": {
			bindings:        binding(authz.Policy{Level: authz.LevelUnspecified}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "no access level"},
		},
		"a procedure declares an unknown access level": {
			bindings:        binding(authz.Policy{Level: authz.Level(9)}),
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidPolicy},
			wantErrContains: []string{testProcedure, "unknown access level"},
		},
		"an introspection override names an unregistered procedure": {
			bindings: binding(authz.Policy{
				Level:     authz.LevelAuthenticated,
				TokenUses: []string{internaljwt.TokenUseTenantAccess},
			}),
			overrides:       registry.Overrides{Introspection: []string{"/test.v1.Service/Absent"}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidOverride},
			wantErrContains: []string{"/test.v1.Service/Absent", "not registered"},
		},
		"an introspection override is listed twice": {
			bindings: binding(authz.Policy{
				Level:     authz.LevelAuthenticated,
				TokenUses: []string{internaljwt.TokenUseTenantAccess},
			}),
			overrides:       registry.Overrides{Introspection: []string{testProcedure, testProcedure}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidOverride},
			wantErrContains: []string{testProcedure, "more than once"},
		},
		"an introspection override names a procedure without an external token": {
			bindings:        binding(authz.Policy{Level: authz.LevelPublic}),
			overrides:       registry.Overrides{Introspection: []string{testProcedure}},
			services:        []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method"}}}},
			wantErrs:        []error{registry.ErrInvalidOverride},
			wantErrContains: []string{testProcedure, "external token"},
		},
		"several problems are reported together": {
			bindings: []registry.Binding{
				{Service: "", Destination: testDestination, Policies: authz.Policies{testProcedure: {Level: authz.LevelPublic}}},
				{Service: testService, Destination: testDestination, Policies: authz.Policies{
					testProcedure:             {Level: authz.LevelAuthenticated},
					"/test.v1.Service/Absent": {Level: authz.LevelPublic},
				}},
			},
			overrides: registry.Overrides{Introspection: []string{"/test.v1.Service/Unknown"}},
			services:  []serviceSpec{{name: "Service", methods: []methodSpec{{name: "Method", streamingServer: true}}}},
			wantErrs: []error{
				registry.ErrInvalidBinding,
				registry.ErrProcedureMismatch,
				registry.ErrStreamingProcedure,
				registry.ErrInvalidPolicy,
				registry.ErrInvalidOverride,
			},
			wantErrContains: []string{"binding 1", "/test.v1.Service/Absent", "/test.v1.Service/Unknown"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			built, err := registry.Build(tt.bindings, tt.overrides, newResolver(t, tt.services...))
			if err == nil {
				t.Fatalf("Build() error = nil, want error")
			}

			if built != nil {
				t.Errorf("Build() registry = %v, want nil", built)
			}

			for _, want := range tt.wantErrs {
				if !errors.Is(err, want) {
					t.Errorf("Build() error = %v, want it to match %v", err, want)
				}
			}

			for _, want := range tt.wantErrContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Build() error = %q, want it to mention %q", err.Error(), want)
				}
			}
		})
	}
}

func TestBuildCopiesItsInput(t *testing.T) {
	t.Parallel()

	scopes := []string{"greeting.read"}
	tokenUses := []string{internaljwt.TokenUseTenantAccess, internaljwt.TokenUseService}
	policies := authz.Policies{testProcedure: {
		Level:          authz.LevelAuthenticated,
		RequiredScopes: scopes,
		TokenUses:      tokenUses,
	}}
	bindings := []registry.Binding{{Service: testService, Destination: testDestination, Policies: policies}}

	built, err := registry.Build(bindings, registry.Overrides{}, singleMethodResolver(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	scopes[0] = "mutated"
	tokenUses[0] = "mutated"
	bindings[0].Destination = "mutated"

	delete(policies, testProcedure)

	got, ok := built.Lookup(testProcedure)
	if !ok {
		t.Fatalf("Lookup(%q) = _, false, want true", testProcedure)
	}

	assertEntry(t, got, registry.Entry{
		Procedure:         testProcedure,
		Destination:       testDestination,
		Anonymous:         false,
		ExternalTokenUses: []string{internaljwt.TokenUseTenantAccess},
		Service:           true,
		RequiredScopes:    []string{"greeting.read"},
		Introspection:     false,
	})

	got.RequiredScopes[0] = "mutated"
	got.ExternalTokenUses[0] = "mutated"

	again, _ := built.Lookup(testProcedure)
	assertEntry(t, again, registry.Entry{
		Procedure:         testProcedure,
		Destination:       testDestination,
		Anonymous:         false,
		ExternalTokenUses: []string{internaljwt.TokenUseTenantAccess},
		Service:           true,
		RequiredScopes:    []string{"greeting.read"},
		Introspection:     false,
	})
}

func TestLookupReportsUnknownProcedures(t *testing.T) {
	t.Parallel()

	built, err := registry.Build(binding(authz.Policy{Level: authz.LevelPublic}), registry.Overrides{}, singleMethodResolver(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	if _, ok := built.Lookup("/test.v1.Service/Absent"); ok {
		t.Errorf("Lookup() = _, true, want false")
	}
}

func TestEntriesAndDestinationsAreOrdered(t *testing.T) {
	t.Parallel()

	bindings := []registry.Binding{
		{Service: "test.v1.Other", Destination: "tolo-other", Policies: authz.Policies{
			"/test.v1.Other/Beta":  {Level: authz.LevelPublic},
			"/test.v1.Other/Alpha": {Level: authz.LevelPublic},
		}},
		{Service: testService, Destination: testDestination, Policies: authz.Policies{
			testProcedure: {Level: authz.LevelPublic},
		}},
	}

	built, err := registry.Build(bindings, registry.Overrides{}, newResolver(t,
		serviceSpec{name: "Service", methods: []methodSpec{{name: "Method"}}},
		serviceSpec{name: "Other", methods: []methodSpec{{name: "Alpha"}, {name: "Beta"}}},
	))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	wantProcedures := []string{"/test.v1.Other/Alpha", "/test.v1.Other/Beta", testProcedure}

	gotProcedures := make([]string, 0, len(wantProcedures))
	for _, entry := range built.Entries() {
		gotProcedures = append(gotProcedures, entry.Procedure)
	}

	if !slices.Equal(gotProcedures, wantProcedures) {
		t.Errorf("Entries() procedures = %v, want %v", gotProcedures, wantProcedures)
	}

	if got, want := built.Destinations(), []string{"tolo-other", testDestination}; !slices.Equal(got, want) {
		t.Errorf("Destinations() = %v, want %v", got, want)
	}
}

func TestSnapshotFormat(t *testing.T) {
	t.Parallel()

	bindings := []registry.Binding{{
		Service:     testService,
		Destination: testDestination,
		Policies: authz.Policies{
			testProcedure: {
				Level:          authz.LevelAuthenticated,
				RequiredScopes: []string{"greeting.read", "greeting.write"},
				TokenUses:      []string{internaljwt.TokenUseTenantAccess, internaljwt.TokenUseService},
			},
			"/test.v1.Service/Anonymous": {Level: authz.LevelPublic},
		},
	}}

	built, err := registry.Build(bindings, registry.Overrides{Introspection: []string{testProcedure}}, newResolver(t,
		serviceSpec{name: "Service", methods: []methodSpec{{name: "Method"}, {name: "Anonymous"}}},
	))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	want := strings.Join([]string{
		"/test.v1.Service/Anonymous\tdestination=tolo-testbackend\tanonymous=true\texternal=-\tservice=false\tscopes=-\tintrospection=false",
		"/test.v1.Service/Method\tdestination=tolo-testbackend\tanonymous=false\texternal=tenant_access\tservice=true\tscopes=greeting.read,greeting.write\tintrospection=true",
		"",
	}, "\n")

	if got := built.Snapshot(); got != want {
		t.Errorf("Snapshot() = %q, want %q", got, want)
	}
}
