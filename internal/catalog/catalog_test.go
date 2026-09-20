package catalog_test

import (
	"flag"
	"os"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/edgepolicy"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	goldenPath    = "testdata/registry.golden"
	edgesPath     = "testdata/edges.golden"
	updateCommand = "go test ./internal/catalog -update"
)

var update = flag.Bool("update", false, "rewrite the golden registry snapshot")

func buildRegistry(t *testing.T) *registry.Registry {
	t.Helper()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	return built
}

func compareGolden(t *testing.T, path, got string) {
	t.Helper()

	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}

		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if got != string(want) {
		t.Errorf("the snapshot does not match %s\ngot:\n%s\nwant:\n%s\nrun `%s` to update it", path, got, want, updateCommand)
	}
}

func TestSnapshotMatchesGolden(t *testing.T) {
	t.Parallel()

	compareGolden(t, goldenPath, buildRegistry(t).Snapshot())
}

func TestEdgeSnapshotMatchesGolden(t *testing.T) {
	t.Parallel()

	policy, err := edgepolicy.Build(catalog.Edges(), buildRegistry(t))
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	compareGolden(t, edgesPath, policy.Snapshot())
}
