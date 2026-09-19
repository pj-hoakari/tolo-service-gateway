package tenantctx_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "github.com/pj-hoakari/internal-jwt-handling"

	"github.com/pj-hoakari/go-service-template/internal/tenantctx"
)

// withTenant returns a context carrying verified claims that authenticate the
// given tenant, as the transport interceptor would.
func withTenant(ctx context.Context, tenantPublicID string) context.Context {
	return internaljwt.ContextWithClaims(ctx, internaljwt.Claims{TenantPublicID: tenantPublicID})
}

// withSubject returns a context carrying verified claims that authenticate the
// given subject but no tenant.
func withSubject(ctx context.Context, subject string) context.Context {
	return internaljwt.ContextWithClaims(ctx, internaljwt.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: subject},
	})
}

func TestSubjectFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ctx    context.Context
		want   string
		wantOK bool
	}{
		{
			name:   "verified subject",
			ctx:    withSubject(context.Background(), "user-1"),
			want:   "user-1",
			wantOK: true,
		},
		{
			name:   "no claims",
			ctx:    context.Background(),
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty subject claim",
			ctx:    withSubject(context.Background(), ""),
			want:   "",
			wantOK: false,
		},
		{
			name:   "blank subject claim",
			ctx:    withSubject(context.Background(), "   "),
			want:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tenantctx.SubjectFromContext(tt.ctx)
			if ok != tt.wantOK {
				t.Errorf("SubjectFromContext() ok = %v, want %v", ok, tt.wantOK)
			}

			if got != tt.want {
				t.Errorf("SubjectFromContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTenantPublicIDFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ctx    context.Context
		want   string
		wantOK bool
	}{
		{
			name:   "verified tenant",
			ctx:    withTenant(context.Background(), "tenant-public-id"),
			want:   "tenant-public-id",
			wantOK: true,
		},
		{
			name:   "no claims",
			ctx:    context.Background(),
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty tenant claim",
			ctx:    withTenant(context.Background(), ""),
			want:   "",
			wantOK: false,
		},
		{
			name:   "blank tenant claim",
			ctx:    withTenant(context.Background(), "   "),
			want:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tenantctx.TenantPublicIDFromContext(tt.ctx)
			if ok != tt.wantOK {
				t.Errorf("TenantPublicIDFromContext() ok = %v, want %v", ok, tt.wantOK)
			}

			if got != tt.want {
				t.Errorf("TenantPublicIDFromContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnsure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		ctx            context.Context
		tenantPublicID string
		wantErr        error
	}{
		{
			name:           "matches context tenant",
			ctx:            withTenant(context.Background(), "tenant-public-id"),
			tenantPublicID: "tenant-public-id",
			wantErr:        nil,
		},
		{
			name:           "differs from context tenant",
			ctx:            withTenant(context.Background(), "tenant-public-id"),
			tenantPublicID: "other-tenant-public-id",
			wantErr:        tenantctx.ErrMismatch,
		},
		{
			name:           "missing context tenant",
			ctx:            context.Background(),
			tenantPublicID: "tenant-public-id",
			wantErr:        tenantctx.ErrMissing,
		},
		{
			name:           "empty context tenant",
			ctx:            withTenant(context.Background(), ""),
			tenantPublicID: "tenant-public-id",
			wantErr:        tenantctx.ErrMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tenantctx.Ensure(tt.ctx, tt.tenantPublicID)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Ensure() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOwnership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		ctx            context.Context
		tenantPublicID string
		wantErr        error
	}{
		{
			name:           "matches context tenant",
			ctx:            withTenant(context.Background(), "tenant-public-id"),
			tenantPublicID: "tenant-public-id",
			wantErr:        nil,
		},
		{
			name:           "differs from context tenant",
			ctx:            withTenant(context.Background(), "tenant-public-id"),
			tenantPublicID: "other-tenant-public-id",
			wantErr:        tenantctx.ErrMismatch,
		},
		{
			name:           "missing context tenant is unrestricted",
			ctx:            context.Background(),
			tenantPublicID: "tenant-public-id",
			wantErr:        nil,
		},
		{
			name:           "empty context tenant is unrestricted",
			ctx:            withTenant(context.Background(), ""),
			tenantPublicID: "tenant-public-id",
			wantErr:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tenantctx.VerifyOwnership(tt.ctx, tt.tenantPublicID)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyOwnership() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
