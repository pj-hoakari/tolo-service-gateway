package httpapi_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/pj-hoakari/tolo-service-gateway/internal/infra/httpapi"
)

func TestNewServerAcceptsHTTP1AndPriorKnowledgeH2C(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := httpapi.NewServer(listener.Addr().String(), httpapi.NewHandler(httpapi.HealthRoutes(httpapi.NewReadiness())))

	go func() { _ = server.Serve(listener) }()

	t.Cleanup(func() { _ = server.Close() })

	for _, tc := range []struct {
		name      string
		protocol  func(*http.Protocols)
		wantMajor int
	}{
		{name: "HTTP/1.1", protocol: func(p *http.Protocols) { p.SetHTTP1(true) }, wantMajor: 1},
		{name: "h2c with prior knowledge", protocol: func(p *http.Protocols) { p.SetUnencryptedHTTP2(true) }, wantMajor: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var protocols http.Protocols
			tc.protocol(&protocols)

			client := &http.Client{Transport: &http.Transport{Protocols: &protocols}}

			res, err := client.Get("http://" + listener.Addr().String() + "/healthz")
			if err != nil {
				t.Fatalf("GET /healthz: %v", err)
			}
			defer res.Body.Close()

			if got, want := res.StatusCode, http.StatusOK; got != want {
				t.Errorf("status = %d, want %d", got, want)
			}

			if got := res.ProtoMajor; got != tc.wantMajor {
				t.Errorf("proto = %s, want HTTP/%d", res.Proto, tc.wantMajor)
			}
		})
	}
}
