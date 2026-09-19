// Package tenantctx reads the authenticated principal's facts (the subject and
// the tenant's public ID) from the request context and verifies that
// tenant-scoped work targets that tenant.
//
// The facts arrive as the claims of the internal JWT that the transport
// interceptor (internal-jwt-handling/interceptor) verified for the call. This
// package is read-only: it exposes only the claims that may drive an
// authorization decision, keeping the raw claim set out of the application
// layer, and pairs them with the tenant boundary checks Ensure and
// VerifyOwnership.
//
// It is deliberately kept out of the domain layer: whether a caller may act on
// a given tenant is contextual authorization, not an intrinsic domain
// invariant, so domain value objects stay free of request context.
package tenantctx

import (
	"context"
	"errors"
	"strings"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"
)

var (
	// ErrMissing indicates the authenticated tenant ID is absent from the
	// context on an operation that requires it.
	ErrMissing = errors.New("tenant ID is missing from context")
	// ErrSubjectMissing indicates the authenticated subject is absent from the
	// context on an operation that requires it.
	ErrSubjectMissing = errors.New("subject is missing from context")
	// ErrMismatch indicates a tenant-scoped operation targets a tenant other
	// than the authenticated one carried in the context.
	ErrMismatch = errors.New("tenant ID does not match context")
)

// SubjectFromContext returns the authenticated subject carried in the verified
// internal JWT's sub claim.
func SubjectFromContext(ctx context.Context) (string, bool) {
	claims, ok := internaljwt.ClaimsFromContext(ctx)
	if !ok {
		return "", false
	}

	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		return "", false
	}

	return subject, true
}

// TenantPublicIDFromContext returns the authenticated tenant's public ID
// carried in the verified internal JWT's tenant_id claim.
func TenantPublicIDFromContext(ctx context.Context) (string, bool) {
	claims, ok := internaljwt.ClaimsFromContext(ctx)
	if !ok {
		return "", false
	}

	tenantPublicID := strings.TrimSpace(claims.TenantPublicID)
	if tenantPublicID == "" {
		return "", false
	}

	return tenantPublicID, true
}

// Ensure verifies that tenantPublicID matches the authenticated tenant carried
// in the context. It fails closed: a missing context tenant ID is an error, so
// tenant-scoped work never proceeds without a verified owner. Callers pass the
// public ID of the tenant they are about to act on to guard against tenant
// mix-ups. Use this at the use-case boundary to authorize an operation.
func Ensure(ctx context.Context, tenantPublicID string) error {
	contextTenantPublicID, ok := TenantPublicIDFromContext(ctx)
	if !ok || contextTenantPublicID == "" {
		return ErrMissing
	}

	if contextTenantPublicID != tenantPublicID {
		return ErrMismatch
	}

	return nil
}

// VerifyOwnership guards a tenant-scoped model reconstituted from persistence
// against the authenticated tenant. Unlike Ensure it fails open on a missing
// context tenant: operations that legitimately run without an authenticated
// tenant (e.g. service-token reads) stay unrestricted. It exists as defense in
// depth, so that a repository query which forgets to scope by tenant cannot
// hand back — and thereby leak — another tenant's data.
func VerifyOwnership(ctx context.Context, tenantPublicID string) error {
	contextTenantPublicID, ok := TenantPublicIDFromContext(ctx)
	if !ok || contextTenantPublicID == "" {
		return nil
	}

	if contextTenantPublicID != tenantPublicID {
		return ErrMismatch
	}

	return nil
}
