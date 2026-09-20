package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

const JWKSPath = "/.well-known/jwks.json"

const (
	jwksCacheControl   = "public, max-age=300"
	jwksContentType    = "application/json"
	jwksUnavailableMsg = "jwks unavailable"
)

type JWKSSource interface {
	JWKS(ctx context.Context) (internaljwt.JWKS, error)
}

func NewJWKSHandler(source JWKSSource) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		body, err := encodeJWKS(ctx, source)
		if err != nil {
			slog.ErrorContext(ctx, "build JWKS failed", "error", err)
			writeJWKSUnavailable(ctx, w)

			return
		}

		header := w.Header()
		header.Set("Content-Type", jwksContentType)
		header.Set("Cache-Control", jwksCacheControl)
		header.Set("ETag", jwksETag(body))

		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	})
}

func encodeJWKS(ctx context.Context, source JWKSSource) ([]byte, error) {
	document, err := source.JWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the internal JWT verification keys: %w", err)
	}

	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode the JWKS document: %w", err)
	}

	return encoded, nil
}

func jwksETag(body []byte) string {
	sum := sha256.Sum256(body)

	return `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
}

func writeJWKSUnavailable(ctx context.Context, w http.ResponseWriter) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", "text/plain; charset=utf-8")

	w.WriteHeader(http.StatusServiceUnavailable)

	if _, err := w.Write([]byte(jwksUnavailableMsg)); err != nil {
		slog.ErrorContext(ctx, "jwks response write failed", "error", err)
	}
}
