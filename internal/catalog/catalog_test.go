package catalog_test

import (
	"flag"
	"os"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const (
	goldenPath    = "testdata/registry.golden"
	updateCommand = "go test ./internal/catalog -update"
)

var update = flag.Bool("update", false, "rewrite the golden registry snapshot")

func TestSnapshotMatchesGolden(t *testing.T) {
	t.Parallel()

	built, err := registry.Build(catalog.Bindings(), catalog.Overrides(), protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("Build() error = %v, want nil", err)
	}

	got := built.Snapshot()

	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o600); err != nil {
			t.Fatalf("write %s: %v", goldenPath, err)
		}

		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenPath, err)
	}

	if got != string(want) {
		t.Errorf("the registry snapshot does not match %s\ngot:\n%s\nwant:\n%s\nrun `%s` to update it", goldenPath, got, want, updateCommand)
	}
}
