package connect

import (
	"context"

	connectrpc "connectrpc.com/connect"

	"github.com/pj-hoakari/tolo-service-gateway/internal/audit"
)

const resultOK = "ok"

func AuditInterceptor() connectrpc.Interceptor {
	return auditInterceptor{}
}

type auditInterceptor struct{}

func (auditInterceptor) WrapUnary(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		res, err := next(ctx, req)

		if record := audit.FromContext(ctx); record != nil {
			record.Result = resultOf(err)
		}

		return res, err
	}
}

func (auditInterceptor) WrapStreamingClient(next connectrpc.StreamingClientFunc) connectrpc.StreamingClientFunc {
	return next
}

func (auditInterceptor) WrapStreamingHandler(next connectrpc.StreamingHandlerFunc) connectrpc.StreamingHandlerFunc {
	return next
}

func resultOf(err error) string {
	if err == nil {
		return resultOK
	}

	return connectrpc.CodeOf(err).String()
}
