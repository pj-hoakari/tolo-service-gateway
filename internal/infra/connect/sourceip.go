package connect

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const forwardedForHeader = "X-Forwarded-For"

func sourceIP(r *http.Request, trustedProxyHops int) string {
	if trustedProxyHops > 0 {
		if forwarded, ok := forwardedFor(r.Header, trustedProxyHops); ok {
			return forwarded
		}
	}

	return remoteHost(r.RemoteAddr)
}

func forwardedFor(header http.Header, trustedProxyHops int) (string, bool) {
	var addresses []string

	for _, value := range header.Values(forwardedForHeader) {
		for _, address := range strings.Split(value, ",") {
			addresses = append(addresses, strings.TrimSpace(address))
		}
	}

	if len(addresses) < trustedProxyHops {
		return "", false
	}

	address := addresses[len(addresses)-trustedProxyHops]
	if _, err := netip.ParseAddr(address); err != nil {
		return "", false
	}

	return address, true
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}
