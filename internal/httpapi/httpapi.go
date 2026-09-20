package httpapi

import (
	"net/http"
)

type Routes func(mux *http.ServeMux)

func NewHandler(routes ...Routes) http.Handler {
	mux := http.NewServeMux()

	for _, route := range routes {
		route(mux)
	}

	return mux
}

func PublicRoutes(jwks http.Handler) Routes {
	return func(mux *http.ServeMux) {
		mux.Handle("GET "+JWKSPath, jwks)
	}
}

func WorkloadRoutes() Routes {
	return func(_ *http.ServeMux) {}
}
