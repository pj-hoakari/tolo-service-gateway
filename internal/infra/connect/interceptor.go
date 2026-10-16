package connect

import (
	"context"

	connectrpc "connectrpc.com/connect/v2"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
)

const resultOK = "ok"

func AuditInterceptor() connectrpc.ServerInterceptor {
	return func(next connectrpc.ServerFunc) connectrpc.ServerFunc {
		return func(ctx context.Context, spec connectrpc.Spec, stream connectrpc.ServerStream) error {
			err := next(ctx, spec, stream)

			if record := audit.FromContext(ctx); record != nil {
				record.Result = resultOf(err)
			}

			return err
		}
	}
}

func resultOf(err error) string {
	if err == nil {
		return resultOK
	}

	return connectrpc.CodeOf(err).String()
}
