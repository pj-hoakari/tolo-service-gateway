package forwardgen_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/connect/forwardgen"
)

func TestMountsCoverExactlyTheBoundServices(t *testing.T) {
	t.Parallel()

	bound := make(map[string]struct{})
	for _, binding := range catalog.Bindings() {
		bound[binding.Service] = struct{}{}
	}

	mounted := make(map[string]struct{})
	for _, mount := range forwardgen.Mounts() {
		mounted[mount.Service] = struct{}{}
	}

	got, want := slices.Sorted(maps.Keys(mounted)), slices.Sorted(maps.Keys(bound))
	if !slices.Equal(got, want) {
		t.Errorf("mounted services = %v, want %v", got, want)
	}
}

func TestMountsAreOrderedByService(t *testing.T) {
	t.Parallel()

	services := make([]string, 0, len(forwardgen.Mounts()))
	for _, mount := range forwardgen.Mounts() {
		services = append(services, mount.Service)
	}

	if !slices.IsSorted(services) {
		t.Errorf("mounted services = %v, want them sorted", services)
	}
}
