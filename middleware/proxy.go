package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"

	"github.com/realclientip/realclientip-go"
)

// proxyHeaders are the request headers honoured only when a trusted proxy sent them.
var proxyHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", RequestIDHeader}

// clientIPKey is the request context key under which ProxyTrust.Handler records the client IP.
type clientIPKey struct{}

// ProxyTrust resolves each request's client IP, honouring proxy headers only from trusted proxy peers.
type ProxyTrust struct {
	trusted  []net.IPNet
	strategy realclientip.RightmostTrustedRangeStrategy
}

// NewProxyTrust creates a ProxyTrust that trusts peers within the given IP addresses and CIDR ranges.
func NewProxyTrust(proxies []string) (*ProxyTrust, error) {
	trusted, err := realclientip.AddressesAndRangesToIPNets(proxies...)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted proxies: %w", err)
	}
	strategy, err := realclientip.NewRightmostTrustedRangeStrategy("X-Forwarded-For", trusted)
	if err != nil {
		return nil, fmt.Errorf("creating client IP strategy: %w", err)
	}
	return &ProxyTrust{trusted: trusted, strategy: strategy}, nil
}

// Handler removes proxy headers sent by untrusted peers and records the client IP for ClientIP.
func (p *ProxyTrust) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := peerIP(r)
		if p.trusts(ip) {
			if forwarded := p.strategy.ClientIP(r.Header, r.RemoteAddr); forwarded != "" {
				ip = forwarded
			}
		} else {
			for _, name := range proxyHeaders {
				r.Header.Del(name)
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip)))
	})
}

// trusts reports whether ip falls within a trusted proxy range.
func (p *ProxyTrust) trusts(ip string) bool {
	addr, err := realclientip.ParseIPAddr(ip)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(p.trusted, func(n net.IPNet) bool { return n.Contains(addr.IP) })
}

// peerIP returns the IP address of the connection's remote end, without its port.
func peerIP(r *http.Request) string {
	return realclientip.RemoteAddrStrategy{}.ClientIP(nil, r.RemoteAddr)
}

// ClientIP returns the client IP recorded by ProxyTrust.Handler, falling back to the connection's remote address.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok && ip != "" {
		return ip
	}
	if ip := peerIP(r); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
