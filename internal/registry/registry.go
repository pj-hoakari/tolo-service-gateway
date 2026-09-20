package registry

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
	"github.com/pj-hoakari/protoc-gen-authz-go/authz"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	ErrInvalidBinding     = errors.New("registry: invalid binding")
	ErrDuplicateProcedure = errors.New("registry: duplicate procedure")
	ErrServiceDescriptor  = errors.New("registry: service descriptor")
	ErrProcedureMismatch  = errors.New("registry: procedure mismatch")
	ErrStreamingProcedure = errors.New("registry: streaming procedure")
	ErrInvalidPolicy      = errors.New("registry: invalid policy")
	ErrInvalidOverride    = errors.New("registry: invalid override")
)

const emptyListMark = "-"

type Binding struct {
	Service     string
	Destination string
	Policies    authz.Policies
}

type Overrides struct {
	Introspection []string
}

type Entry struct {
	Procedure         string
	Destination       string
	Anonymous         bool
	ExternalTokenUses []string
	Service           bool
	RequiredScopes    []string
	Introspection     bool
}

type DescriptorResolver interface {
	FindDescriptorByName(name protoreflect.FullName) (protoreflect.Descriptor, error)
}

type Registry struct {
	entries map[string]Entry
	order   []string
}

func Build(bindings []Binding, overrides Overrides, resolver DescriptorResolver) (*Registry, error) {
	entries := make(map[string]Entry, len(bindings))
	boundServices := make(map[string]struct{}, len(bindings))

	var errs []error

	for index, binding := range bindings {
		if err := checkBinding(index, binding, boundServices); err != nil {
			errs = append(errs, err)

			continue
		}

		boundServices[binding.Service] = struct{}{}
		errs = append(errs, checkDescriptor(binding, resolver)...)
		errs = append(errs, addBinding(entries, binding)...)
	}

	errs = append(errs, applyOverrides(entries, overrides)...)

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return &Registry{entries: entries, order: slices.Sorted(maps.Keys(entries))}, nil
}

func checkBinding(index int, binding Binding, boundServices map[string]struct{}) error {
	if binding.Service == "" {
		return fmt.Errorf("%w: binding %d declares no service", ErrInvalidBinding, index+1)
	}

	if binding.Destination == "" {
		return fmt.Errorf("%w: %s declares no destination", ErrInvalidBinding, binding.Service)
	}

	if len(binding.Policies) == 0 {
		return fmt.Errorf("%w: %s declares no policy", ErrInvalidBinding, binding.Service)
	}

	if _, bound := boundServices[binding.Service]; bound {
		return fmt.Errorf("%w: %s is bound more than once", ErrInvalidBinding, binding.Service)
	}

	return nil
}

func addBinding(entries map[string]Entry, binding Binding) []error {
	var errs []error

	for _, procedure := range slices.Sorted(maps.Keys(binding.Policies)) {
		if _, bound := entries[procedure]; bound {
			errs = append(errs, fmt.Errorf("%w: %s is bound more than once", ErrDuplicateProcedure, procedure))

			continue
		}

		entry, err := deriveEntry(procedure, binding.Destination, binding.Policies[procedure])
		if err != nil {
			errs = append(errs, err)

			continue
		}

		entries[procedure] = entry
	}

	return errs
}

func checkDescriptor(binding Binding, resolver DescriptorResolver) []error {
	descriptor, err := resolver.FindDescriptorByName(protoreflect.FullName(binding.Service))
	if err != nil {
		return []error{fmt.Errorf("%w: %s cannot be resolved: %w", ErrServiceDescriptor, binding.Service, err)}
	}

	service, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return []error{fmt.Errorf("%w: %s is not a service", ErrServiceDescriptor, binding.Service)}
	}

	var errs []error

	methods := service.Methods()
	declared := make(map[string]struct{}, methods.Len())

	for index := range methods.Len() {
		method := methods.Get(index)
		procedure := procedureOf(binding.Service, string(method.Name()))
		declared[procedure] = struct{}{}

		if method.IsStreamingClient() || method.IsStreamingServer() {
			errs = append(errs, fmt.Errorf("%w: %s is a streaming procedure", ErrStreamingProcedure, procedure))
		}

		if _, ok := binding.Policies[procedure]; !ok {
			errs = append(errs, fmt.Errorf("%w: %s is declared by the descriptor but has no policy", ErrProcedureMismatch, procedure))
		}
	}

	for _, procedure := range slices.Sorted(maps.Keys(binding.Policies)) {
		if _, ok := declared[procedure]; !ok {
			errs = append(errs, fmt.Errorf("%w: %s has a policy but is not declared by the descriptor", ErrProcedureMismatch, procedure))
		}
	}

	return errs
}

func applyOverrides(entries map[string]Entry, overrides Overrides) []error {
	var errs []error

	seen := make(map[string]struct{}, len(overrides.Introspection))

	for _, procedure := range overrides.Introspection {
		if _, duplicate := seen[procedure]; duplicate {
			errs = append(errs, fmt.Errorf("%w: %s is listed for introspection more than once", ErrInvalidOverride, procedure))

			continue
		}

		seen[procedure] = struct{}{}

		entry, registered := entries[procedure]
		if !registered {
			errs = append(errs, fmt.Errorf("%w: %s is listed for introspection but is not registered", ErrInvalidOverride, procedure))

			continue
		}

		if len(entry.ExternalTokenUses) == 0 {
			errs = append(errs, fmt.Errorf("%w: %s is listed for introspection but accepts no external token", ErrInvalidOverride, procedure))

			continue
		}

		entry.Introspection = true
		entries[procedure] = entry
	}

	return errs
}

func deriveEntry(procedure, destination string, policy authz.Policy) (Entry, error) {
	var zero Entry

	accepted, err := deriveSubjects(procedure, policy)
	if err != nil {
		return zero, err
	}

	return Entry{
		Procedure:         procedure,
		Destination:       destination,
		Anonymous:         accepted.anonymous,
		ExternalTokenUses: accepted.externalTokenUses,
		Service:           accepted.service,
		RequiredScopes:    slices.Clone(policy.RequiredScopes),
		Introspection:     false,
	}, nil
}

type subjects struct {
	anonymous         bool
	externalTokenUses []string
	service           bool
}

func deriveSubjects(procedure string, policy authz.Policy) (subjects, error) {
	var zero subjects

	switch policy.Level {
	case authz.LevelPublic:
		if len(policy.TokenUses) > 0 {
			return zero, fmt.Errorf("%w: %s is public but declares token uses", ErrInvalidPolicy, procedure)
		}

		if len(policy.RequiredScopes) > 0 {
			return zero, fmt.Errorf("%w: %s is public but declares required scopes", ErrInvalidPolicy, procedure)
		}

		return subjects{anonymous: true, externalTokenUses: nil, service: false}, nil
	case authz.LevelInternal:
		if !isServiceOnly(policy.TokenUses) {
			return zero, fmt.Errorf("%w: %s is internal but declares token uses other than %q", ErrInvalidPolicy, procedure, internaljwt.TokenUseService)
		}

		return subjects{anonymous: false, externalTokenUses: nil, service: true}, nil
	case authz.LevelAuthenticated:
		return authenticatedSubjects(procedure, policy.TokenUses)
	case authz.LevelUnspecified:
		return zero, fmt.Errorf("%w: %s declares no access level", ErrInvalidPolicy, procedure)
	default:
		return zero, fmt.Errorf("%w: %s declares the unknown access level %d", ErrInvalidPolicy, procedure, int(policy.Level))
	}
}

func authenticatedSubjects(procedure string, tokenUses []string) (subjects, error) {
	var zero subjects

	if len(tokenUses) == 0 {
		return zero, fmt.Errorf("%w: %s is authenticated but declares no token use", ErrInvalidPolicy, procedure)
	}

	external := make([]string, 0, len(tokenUses))
	seen := make(map[string]struct{}, len(tokenUses))
	acceptsService := false

	for _, tokenUse := range tokenUses {
		if !isKnownTokenUse(tokenUse) {
			return zero, fmt.Errorf("%w: %s declares the unknown token use %q", ErrInvalidPolicy, procedure, tokenUse)
		}

		if _, duplicate := seen[tokenUse]; duplicate {
			return zero, fmt.Errorf("%w: %s declares the token use %q more than once", ErrInvalidPolicy, procedure, tokenUse)
		}

		seen[tokenUse] = struct{}{}

		if tokenUse == internaljwt.TokenUseService {
			acceptsService = true

			continue
		}

		external = append(external, tokenUse)
	}

	if len(external) == 0 {
		return zero, fmt.Errorf("%w: %s accepts only %q and must be declared internal instead", ErrInvalidPolicy, procedure, internaljwt.TokenUseService)
	}

	return subjects{anonymous: false, externalTokenUses: external, service: acceptsService}, nil
}

func isServiceOnly(tokenUses []string) bool {
	return len(tokenUses) == 0 || (len(tokenUses) == 1 && tokenUses[0] == internaljwt.TokenUseService)
}

func isKnownTokenUse(tokenUse string) bool {
	switch tokenUse {
	case internaljwt.TokenUseTenantAccess, internaljwt.TokenUseEventAccess, internaljwt.TokenUseService, internaljwt.TokenUseRegistration:
		return true
	default:
		return false
	}
}

func procedureOf(service, method string) string {
	return "/" + service + "/" + method
}

func (r *Registry) Lookup(procedure string) (Entry, bool) {
	entry, ok := r.entries[procedure]
	if !ok {
		var zero Entry

		return zero, false
	}

	return cloneEntry(entry), true
}

func (r *Registry) Entries() []Entry {
	entries := make([]Entry, 0, len(r.order))

	for _, procedure := range r.order {
		entries = append(entries, cloneEntry(r.entries[procedure]))
	}

	return entries
}

func (r *Registry) Destinations() []string {
	seen := make(map[string]struct{}, len(r.order))

	for _, procedure := range r.order {
		seen[r.entries[procedure].Destination] = struct{}{}
	}

	return slices.Sorted(maps.Keys(seen))
}

func (r *Registry) Snapshot() string {
	lines := make([]string, 0, len(r.order))

	for _, procedure := range r.order {
		entry := r.entries[procedure]
		lines = append(lines, strings.Join([]string{
			entry.Procedure,
			"destination=" + entry.Destination,
			fmt.Sprintf("anonymous=%t", entry.Anonymous),
			"external=" + formatList(entry.ExternalTokenUses),
			fmt.Sprintf("service=%t", entry.Service),
			"scopes=" + formatList(entry.RequiredScopes),
			fmt.Sprintf("introspection=%t", entry.Introspection),
		}, "\t"))
	}

	if len(lines) == 0 {
		return ""
	}

	return strings.Join(lines, "\n") + "\n"
}

func cloneEntry(entry Entry) Entry {
	entry.ExternalTokenUses = slices.Clone(entry.ExternalTokenUses)
	entry.RequiredScopes = slices.Clone(entry.RequiredScopes)

	return entry
}

func formatList(values []string) string {
	if len(values) == 0 {
		return emptyListMark
	}

	return strings.Join(values, ",")
}
