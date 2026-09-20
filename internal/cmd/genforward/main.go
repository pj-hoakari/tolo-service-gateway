package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"

	"github.com/pj-hoakari/tolo-service-gateway/internal/catalog"
)

var (
	errServiceDescriptor = errors.New("genforward: service descriptor")
	errGeneration        = errors.New("genforward: generation")
)

func main() {
	out := flag.String("out", ".", "directory the forwarding code is written to")

	flag.Parse()

	if err := run(*out); err != nil {
		slog.Error("genforward failed", "error", err)
		os.Exit(1)
	}
}

func run(out string) error {
	services := boundServiceNames()

	request, err := codeGeneratorRequest(services)
	if err != nil {
		return err
	}

	var options protogen.Options

	plugin, err := options.New(request)
	if err != nil {
		return fmt.Errorf("start protogen: %w", err)
	}

	if err := Generate(plugin, services); err != nil {
		return err
	}

	return writeResponse(out, plugin.Response())
}

func boundServiceNames() map[string]struct{} {
	bindings := catalog.Bindings()
	services := make(map[string]struct{}, len(bindings))

	for _, binding := range bindings {
		services[binding.Service] = struct{}{}
	}

	return services
}

func codeGeneratorRequest(services map[string]struct{}) (*pluginpb.CodeGeneratorRequest, error) {
	roots := make(map[string]protoreflect.FileDescriptor, len(services))

	for _, service := range slices.Sorted(maps.Keys(services)) {
		file, err := serviceFile(service)
		if err != nil {
			return nil, err
		}

		roots[file.Path()] = file
	}

	paths := slices.Sorted(maps.Keys(roots))

	var (
		protos []*descriptorpb.FileDescriptorProto
		seen   = make(map[string]struct{})
	)

	for _, root := range paths {
		protos = appendFileAndImports(protos, seen, roots[root])
	}

	return &pluginpb.CodeGeneratorRequest{
		FileToGenerate:        paths,
		Parameter:             nil,
		ProtoFile:             protos,
		SourceFileDescriptors: nil,
		CompilerVersion:       nil,
	}, nil
}

func serviceFile(service string) (protoreflect.FileDescriptor, error) {
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be resolved: %w", errServiceDescriptor, service, err)
	}

	resolved, ok := descriptor.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a service", errServiceDescriptor, service)
	}

	return resolved.ParentFile(), nil
}

func appendFileAndImports(
	protos []*descriptorpb.FileDescriptorProto,
	seen map[string]struct{},
	file protoreflect.FileDescriptor,
) []*descriptorpb.FileDescriptorProto {
	if _, done := seen[file.Path()]; done {
		return protos
	}

	seen[file.Path()] = struct{}{}

	imports := file.Imports()
	for index := range imports.Len() {
		protos = appendFileAndImports(protos, seen, imports.Get(index).FileDescriptor)
	}

	return append(protos, protodesc.ToFileDescriptorProto(file))
}

func writeResponse(out string, response *pluginpb.CodeGeneratorResponse) error {
	if response.GetError() != "" {
		return fmt.Errorf("%w: %s", errGeneration, response.GetError())
	}

	written := make(map[string]struct{}, len(response.GetFile()))

	for _, file := range response.GetFile() {
		name := filepath.Base(file.GetName())
		written[name] = struct{}{}

		if err := os.WriteFile(filepath.Join(out, name), []byte(file.GetContent()), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	return removeStaleFiles(out, written)
}

func removeStaleFiles(out string, written map[string]struct{}) error {
	matches, err := filepath.Glob(filepath.Join(out, "*"+fileSuffix))
	if err != nil {
		return fmt.Errorf("list the generated files in %s: %w", out, err)
	}

	for _, match := range matches {
		if _, kept := written[filepath.Base(match)]; kept {
			continue
		}

		if err := os.Remove(match); err != nil {
			return fmt.Errorf("remove %s: %w", match, err)
		}
	}

	return nil
}
