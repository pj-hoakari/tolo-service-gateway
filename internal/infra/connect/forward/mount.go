package forward

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/registry"
)

const maxRequestBytes = 1 << 20

var (
	ErrMissingMount       = errors.New("forward: missing mount")
	ErrUnboundMount       = errors.New("forward: unbound mount")
	ErrDuplicateMount     = errors.New("forward: duplicate mount")
	ErrDuplicateMountPath = errors.New("forward: duplicate mount path")
)

func Handlers(
	bindings []registry.Binding,
	destinations registry.Destinations,
	mounts []Mount,
	httpClient connectrpc.HTTPClient,
	clientOptions []connectrpc.ClientOption,
	handlerOptions []connectrpc.HandlerOption,
) (map[string]http.Handler, error) {
	bound := make(map[string]string, len(bindings))

	for _, binding := range bindings {
		bound[binding.Service] = binding.Destination
	}

	mounted, err := indexMounts(mounts)
	if err != nil {
		return nil, err
	}

	if err := checkCoverage(bound, mounted); err != nil {
		return nil, err
	}

	options := append([]connectrpc.HandlerOption{connectrpc.WithReadMaxBytes(maxRequestBytes)}, handlerOptions...)
	handlers := make(map[string]http.Handler, len(mounted))

	for _, service := range slices.Sorted(maps.Keys(mounted)) {
		baseURL, err := baseURLOf(service, bound[service], destinations)
		if err != nil {
			return nil, err
		}

		path, handler := mounted[service].New(httpClient, baseURL, clientOptions, options)

		if _, taken := handlers[path]; taken {
			return nil, fmt.Errorf("%w: %s is mounted on %q, which is already taken", ErrDuplicateMountPath, service, path)
		}

		handlers[path] = handler
	}

	return handlers, nil
}

func indexMounts(mounts []Mount) (map[string]Mount, error) {
	mounted := make(map[string]Mount, len(mounts))

	for _, mount := range mounts {
		if _, duplicate := mounted[mount.Service]; duplicate {
			return nil, fmt.Errorf("%w: %s is mounted more than once", ErrDuplicateMount, mount.Service)
		}

		mounted[mount.Service] = mount
	}

	return mounted, nil
}

func checkCoverage(bound map[string]string, mounted map[string]Mount) error {
	var errs []error

	for _, service := range slices.Sorted(maps.Keys(bound)) {
		if _, ok := mounted[service]; !ok {
			errs = append(errs, fmt.Errorf("%w: %s is bound but has no forwarder", ErrMissingMount, service))
		}
	}

	for _, service := range slices.Sorted(maps.Keys(mounted)) {
		if _, ok := bound[service]; !ok {
			errs = append(errs, fmt.Errorf("%w: %s has a forwarder but is not bound", ErrUnboundMount, service))
		}
	}

	return errors.Join(errs...)
}

func baseURLOf(service, destination string, destinations registry.Destinations) (string, error) {
	configured, ok := destinations[destination]
	if !ok {
		return "", fmt.Errorf("%w: %s is bound to %q, which is not configured", registry.ErrMissingDestination, service, destination)
	}

	return strings.TrimRight(configured.URL.String(), "/"), nil
}
