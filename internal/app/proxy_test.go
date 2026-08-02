package app

import (
	"crypto/tls"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSecureRequestUsesNearestTrustedProxyScheme(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	tests := []struct {
		name      string
		remote    string
		xfp       string
		forwarded string
		want      bool
	}{
		{name: "proxy appends HTTPS", remote: "10.0.0.2:443", xfp: "http, https", want: true},
		{name: "proxy appends HTTP", remote: "10.0.0.2:80", xfp: "https, http", want: false},
		{name: "Forwarded chain", remote: "10.0.0.2:443", forwarded: "for=203.0.113.4;proto=http, for=10.0.0.2;proto=https", want: true},
		{name: "untrusted sender", remote: "203.0.113.4:443", xfp: "https", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://idp.example.test/login/123", nil)
			req.RemoteAddr = test.remote
			req.Header.Set("X-Forwarded-Proto", test.xfp)
			req.Header.Set("Forwarded", test.forwarded)
			assert.Equal(t, test.want, isSecureRequest(req, trusted))
		})
	}
}

func TestIsSecureRequestTrustsDirectTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "https://idp.example.test/login/123", nil)
	req.TLS = &tls.ConnectionState{}
	assert.True(t, isSecureRequest(req, nil))
}

func TestClientIPWalksTrustedProxyChainFromRight(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	req := httptest.NewRequest("GET", "https://idp.example.test/login/123", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.4, 10.0.0.3")
	assert.Equal(t, "203.0.113.4", clientIP(req, trusted))
}

func TestForwardingHeadersJoinPhysicalFields(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	req := httptest.NewRequest("GET", "http://idp.example.test/login/123", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header["X-Forwarded-For"] = []string{"198.51.100.9", "203.0.113.4"}
	req.Header["X-Forwarded-Proto"] = []string{"https", "http"}
	req.Header["Forwarded"] = []string{
		"for=198.51.100.9;proto=https",
		"for=203.0.113.4;proto=http",
	}

	assert.Equal(t, "203.0.113.4", clientIP(req, trusted))
	assert.False(t, isSecureRequest(req, trusted))
}

func TestIsSecureRequestFailsClosedOnConflictingSchemeHeaders(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	req := httptest.NewRequest("GET", "http://idp.example.test/login/123", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("Forwarded", "for=203.0.113.4;proto=https")
	assert.False(t, isSecureRequest(req, trusted))

	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "for=203.0.113.4;proto=http")
	assert.False(t, isSecureRequest(req, trusted))
}

func TestIsSecureRequestRejectsDuplicateForwardedProto(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	req := httptest.NewRequest("GET", "http://idp.example.test/login/123", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("Forwarded", "for=203.0.113.4;proto=http;proto=https")
	assert.False(t, isSecureRequest(req, trusted))
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.False(t, isSecureRequest(req, trusted))
}

func TestClientIPUnmapsIPv4MappedIPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "https://idp.example.test/login/123", nil)
	req.RemoteAddr = "[::ffff:203.0.113.4]:443"
	assert.Equal(t, "203.0.113.4", clientIP(req, nil))
}

func TestClientIPIgnoresXRealIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	req := httptest.NewRequest("GET", "https://idp.example.test/login/123", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Real-IP", "203.0.113.4")
	assert.Equal(t, "10.0.0.2", clientIP(req, trusted))
}
