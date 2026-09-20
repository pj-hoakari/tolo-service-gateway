package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
)

var (
	ErrDestinationsFile    = errors.New("registry: destinations file")
	ErrInvalidDestinations = errors.New("registry: invalid destinations")
	ErrMissingDestination  = errors.New("registry: missing destination")
	ErrUnusedDestination   = errors.New("registry: unused destination")
)

type Destination struct {
	URL *url.URL
}

type Destinations map[string]Destination

type destinationsDocument struct {
	Destinations map[string]destinationDocument `json:"destinations"`
}

type destinationDocument struct {
	URL string `json:"url"`
}

func LoadDestinations(path string) (Destinations, error) {
	document, err := readDestinations(path)
	if err != nil {
		return nil, err
	}

	if len(document.Destinations) == 0 {
		return nil, fmt.Errorf("%w: %s declares no destination", ErrInvalidDestinations, path)
	}

	destinations := make(Destinations, len(document.Destinations))

	var errs []error

	for _, id := range slices.Sorted(maps.Keys(document.Destinations)) {
		if id == "" {
			errs = append(errs, fmt.Errorf("%w: %s declares a destination with an empty service ID", ErrInvalidDestinations, path))

			continue
		}

		parsed, err := parseDestinationURL(document.Destinations[id].URL)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %s: destination %q: %w", ErrInvalidDestinations, path, id, err))

			continue
		}

		destinations[id] = Destination{URL: parsed}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return destinations, nil
}

func readDestinations(path string) (destinationsDocument, error) {
	var document destinationsDocument

	raw, err := os.ReadFile(path) //nolint:gosec // the path is operator configuration read once at startup, never request input
	if err != nil {
		return document, fmt.Errorf("%w: %w", ErrDestinationsFile, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("%w: %s: %w", ErrInvalidDestinations, path, err)
	}

	if decoder.More() {
		return document, fmt.Errorf("%w: %s carries data after the top-level object", ErrInvalidDestinations, path)
	}

	return document, nil
}

func parseDestinationURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("the URL is empty")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL: %w", raw, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("the scheme of %q must be http or https", raw)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("%q carries no host", raw)
	}

	if parsed.User != nil {
		return nil, fmt.Errorf("%q must not carry user information", raw)
	}

	if parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, fmt.Errorf("%q must not carry a query", raw)
	}

	if parsed.Fragment != "" {
		return nil, fmt.Errorf("%q must not carry a fragment", raw)
	}

	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("%q must not carry a path", raw)
	}

	return parsed, nil
}

func (r *Registry) CheckDestinations(destinations Destinations) error {
	var errs []error

	referenced := r.Destinations()

	for _, id := range referenced {
		if _, configured := destinations[id]; !configured {
			errs = append(errs, fmt.Errorf("%w: %q is referenced by the registry but not configured", ErrMissingDestination, id))
		}
	}

	for _, id := range slices.Sorted(maps.Keys(destinations)) {
		if !slices.Contains(referenced, id) {
			errs = append(errs, fmt.Errorf("%w: %q is configured but not referenced by the registry", ErrUnusedDestination, id))
		}
	}

	return errors.Join(errs...)
}
