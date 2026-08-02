package app

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func clientIP(r *http.Request, trustedProxies []netip.Prefix) string {
	remote, ok := remoteAddr(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if !isTrustedProxy(remote, trustedProxies) {
		return remote.String()
	}

	if xff := joinedHeaderValues(r.Header, "X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if !isTrustedProxy(addr, trustedProxies) {
				return addr.String()
			}
		}
		for _, part := range parts {
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err == nil {
				return addr.Unmap().String()
			}
		}
	}
	return remote.String()
}

func isSecureRequest(r *http.Request, trustedProxies []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}
	remote, ok := remoteAddr(r.RemoteAddr)
	if !ok || !isTrustedProxy(remote, trustedProxies) {
		return false
	}
	forwardedProto := lastHeaderValue(joinedHeaderValues(r.Header, "X-Forwarded-Proto"))
	forwarded := lastHeaderValue(joinedHeaderValues(r.Header, "Forwarded"))
	proto, forwardedValid := parseForwardedProto(forwarded)
	if forwarded != "" && !forwardedValid {
		return false
	}
	if forwardedProto != "" {
		if forwardedValid && !strings.EqualFold(forwardedProto, proto) {
			return false
		}
		return strings.EqualFold(forwardedProto, "https")
	}
	return forwardedValid && strings.EqualFold(proto, "https")
}

func parseForwardedProto(forwarded string) (string, bool) {
	var proto string
	found := false
	for part := range strings.SplitSeq(forwarded, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(key, "proto") {
			continue
		}
		if found {
			return "", false
		}
		proto = strings.Trim(strings.TrimSpace(value), `"`)
		if proto == "" {
			return "", false
		}
		found = true
	}
	return proto, found
}

func joinedHeaderValues(header http.Header, name string) string {
	return strings.Join(header.Values(name), ",")
}

func lastHeaderValue(value string) string {
	if index := strings.LastIndexByte(value, ','); index >= 0 {
		value = value[index+1:]
	}
	return strings.TrimSpace(value)
}

func isTrustedProxy(addr netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteAddr(value string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
