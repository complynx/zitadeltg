//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/complynx/zitadeltg/internal/app"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

const origin = "https://idp.test"
const audience = origin + "/idps/jwt"
const botID = "123456789"

type harness struct {
	t            *testing.T
	client       *http.Client
	telegram     *app.Signer
	pat          string
	clientID     string
	projectID    string
	appURL       string
	relays       atomic.Int64
	keyDir       string
	stopApp      func()
	appLog       string
	upstreamBody atomic.Value
	prelink      atomic.Pointer[prelinkBackend]
	organization string
}

type flow struct {
	client                                       *http.Client
	state, nonce, verifier, oauthState, bot, idp string
}

// TestCompatibility uses real HTTP, TLS, cookies, the built service binary and
// Zitadel's public APIs. Only Telegram's signing authority is replaced.
func TestCompatibility(t *testing.T) {
	h := newHarness(t)
	h.startApp(t, nil)
	h.bootstrap()

	t.Run("manual_registration_and_returning_user", func(t *testing.T) {
		idp := h.provider(t, "manual", false, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "manual", 1001, nil, nil)
		require.Equal(t, 200, resp.StatusCode, body)
		require.Contains(t, body, "firstname")
		require.Contains(t, strings.Join(resp.Header.Values("Content-Security-Policy"), ";"), "form-action 'self'")
		action, values := form(t, body)
		require.Equal(t, "Jane", values.Get("firstname"))
		require.Equal(t, "Doe", values.Get("lastname"))
		values.Set("firstname", "Edited")
		values.Set("lastname", "Person")
		resp, body = request(t, f.client, "POST", origin+action, values)
		sub := h.finish(t, f, resp, body)
		user := h.api(t, "GET", "/management/v1/users/"+sub, nil)
		require.Equal(t, "Edited", nested(user, "user", "human", "profile", "firstName"))
		links := h.api(t, "POST", "/management/v1/users/"+sub+"/idps/_search", map[string]any{})
		require.Contains(t, fmt.Sprint(links), "telegram:"+botID+":manual")
		f = h.begin(t, idp)
		resp, body = h.authenticate(t, f, "manual", 1001, nil, nil)
		require.Equal(t, 303, resp.StatusCode, body)
		require.Equal(t, sub, h.finish(t, f, resp, body))
	})

	t.Run("automatic_creation_profile_and_phone", func(t *testing.T) {
		idp := h.provider(t, "automatic", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "automatic", 1002, nil, nil)
		sub := h.finish(t, f, resp, body)
		user := h.api(t, "GET", "/management/v1/users/"+sub, nil)
		require.Equal(t, "tg+"+botID+"+1002@telegram.invalid", nested(user, "user", "human", "email", "email"))
		require.Equal(t, true, nested(user, "user", "human", "email", "isEmailVerified"))
		require.Equal(t, "+15555551002", nested(user, "user", "human", "phone", "phone"))
	})

	t.Run("email_auto_linking_matches_existing_user", func(t *testing.T) {
		existing := h.human(t, "email-link", "tg+"+botID+"+1003@telegram.invalid")
		idp := h.provider(t, "email-link", false, false, "AUTO_LINKING_OPTION_EMAIL", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "email-link", 1003, nil, nil)
		require.Equal(t, existing, h.finish(t, f, resp, body))
	})

	for _, update := range []bool{false, true} {
		t.Run(fmt.Sprintf("profile_auto_update_%t", update), func(t *testing.T) {
			idp := h.provider(t, fmt.Sprintf("update-%t", update), true, update, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
			f := h.begin(t, idp)
			resp, body := h.authenticate(t, f, "stable-subject", 1010, nil, nil)
			sub := h.finish(t, f, resp, body)
			f = h.begin(t, idp)
			resp, body = h.authenticate(t, f, "stable-subject", 1010, func(c map[string]any) {
				c["given_name"] = "Changed"
				c["name"] = "Changed Doe"
				c["preferred_username"] = "renamed"
				c["id"] = "1010"
			}, nil)
			require.Equal(t, sub, h.finish(t, f, resp, body))
			user := h.api(t, "GET", "/management/v1/users/"+sub, nil)
			expected := "Jane"
			if update {
				expected = "Changed"
			}
			require.Equal(t, expected, nested(user, "user", "human", "profile", "firstName"))
		})
	}

	t.Run("single_name_profile", func(t *testing.T) {
		idp := h.provider(t, "single-name", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "single-name", 1011, func(c map[string]any) { delete(c, "given_name"); delete(c, "family_name"); c["name"] = "Solo" }, nil)
		sub := h.finish(t, f, resp, body)
		user := h.api(t, "GET", "/management/v1/users/"+sub, nil)
		require.Equal(t, "Solo", nested(user, "user", "human", "profile", "firstName"))
		require.Equal(t, "Solo", nested(user, "user", "human", "profile", "lastName"))
	})

	t.Run("same_telegram_subject_is_isolated_between_bots", func(t *testing.T) {
		first := h.provider(t, "first-bot", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		second := h.providerBot(t, "second-bot", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience, "987654321")
		f := h.begin(t, first)
		resp, body := h.authenticate(t, f, "shared-subject", 1012, nil, nil)
		firstUser := h.finish(t, f, resp, body)
		f = h.begin(t, second)
		resp, body = h.authenticate(t, f, "shared-subject", 1012, nil, nil)
		secondUser := h.finish(t, f, resp, body)
		require.NotEqual(t, firstUser, secondUser)
		user := h.api(t, "GET", "/management/v1/users/"+secondUser, nil)
		require.Equal(t, "tg+987654321+1012@telegram.invalid", nested(user, "user", "human", "email", "email"))
		require.Empty(t, nested(user, "user", "human", "phone"), "unrequested phone must not reach Zitadel")
	})

	t.Run("email_match_does_not_link_when_disabled", func(t *testing.T) {
		h.human(t, "no-email-link", "tg+"+botID+"+1004@telegram.invalid")
		idp := h.provider(t, "no-email-link", false, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "no-email-link", 1004, nil, nil)
		require.Equal(t, 200, resp.StatusCode, body)
		require.Contains(t, body, "firstname")
	})

	t.Run("manual_link_requires_existing_account_authentication", func(t *testing.T) {
		existing := h.human(t, "manual-link", "existing-manual@telegram.invalid")
		idp := h.provider(t, "manual-link", false, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "manual-link", 1013, nil, nil)
		require.Equal(t, 200, resp.StatusCode, body)
		_, values := form(t, body)
		resp, body = request(t, f.client, "POST", origin+"/ui/login/externaluser/option?linkbutton=true", values)
		require.Equal(t, 200, resp.StatusCode, body)
		action, values := form(t, body)
		values.Set("loginName", "manual-link")
		resp, body = request(t, f.client, "POST", origin+action, values)
		require.Equal(t, 200, resp.StatusCode, body)
		action, values = form(t, body)
		require.Contains(t, action, "password")
		values.Set("password", "Integration-Password1!")
		resp, body = request(t, f.client, "POST", origin+action, values)
		if resp.StatusCode == 200 && strings.Contains(body, "<title>Linking User</title>") {
			action, values = form(t, body)
			resp, body = request(t, f.client, "POST", origin+action, values)
		}
		require.Equal(t, existing, h.finish(t, f, resp, body))
		f = h.begin(t, idp)
		resp, body = h.authenticate(t, f, "manual-link", 1013, nil, nil)
		require.Equal(t, existing, h.finish(t, f, resp, body))
	})

	t.Run("audience_enforced_by_real_zitadel", func(t *testing.T) {
		idp := h.provider(t, "wrong-audience", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", "other-audience")
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "wrong-audience", 1005, nil, nil)
		require.Equal(t, 502, resp.StatusCode, body)
	})

	t.Run("empty_provider_audience_preserves_production_behavior", func(t *testing.T) {
		idp := h.provider(t, "empty-audience", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", "")
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "empty-audience", 1006, nil, nil)
		require.NotEmpty(t, h.finish(t, f, resp, body))
	})

	t.Run("no_creation_or_linking_fails_closed", func(t *testing.T) {
		idp := h.provider(t, "closed", false, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		h.api(t, "PUT", "/admin/v1/idps/generic_jwt/"+idp, map[string]any{
			"name": "closed", "issuer": origin + "/tg", "jwtEndpoint": origin + "/tg/login/" + botID,
			"keysEndpoint": origin + "/tg/keys", "headerName": "x-telegram-idp-jwt", "audience": audience,
			"providerOptions": map[string]any{"isCreationAllowed": false, "isLinkingAllowed": false},
		})
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "closed", 1007, nil, nil)
		require.Equal(t, 502, resp.StatusCode, body)
	})

	idp := h.provider(t, "negative", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
	invalid := []struct {
		name   string
		mutate func(map[string]any)
		rogue  bool
	}{
		{"wrong_issuer", func(c map[string]any) { c["iss"] = "https://attacker.test" }, false},
		{"wrong_bot_audience", func(c map[string]any) { c["aud"] = "987654321" }, false},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, false},
		{"future_issued_at", func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }, false},
		{"wrong_nonce", func(c map[string]any) { c["nonce"] = "other" }, false},
		{"missing_id", func(c map[string]any) { delete(c, "id") }, false},
		{"missing_subject", func(c map[string]any) { delete(c, "sub") }, false},
		{"missing_audience", func(c map[string]any) { delete(c, "aud") }, false},
		{"missing_nonce", func(c map[string]any) { delete(c, "nonce") }, false},
		{"invalid_id_string", func(c map[string]any) { c["id"] = "00123" }, false},
		{"oversized_id", func(c map[string]any) { c["id"] = int64(1 << 53) }, false},
		{"insufficient_remaining_lifetime", func(c map[string]any) { c["exp"] = time.Now().Add(2 * time.Second).Unix() }, false},
		{"untrusted_signature", func(c map[string]any) {}, true},
	}
	for _, tc := range invalid {
		t.Run("telegram_"+tc.name, func(t *testing.T) {
			f := h.begin(t, idp)
			before := h.relays.Load()
			var signer *app.Signer
			if tc.rogue {
				var err error
				signer, err = app.NewSigner(app.JWTConfig{KeyID: "rogue"})
				require.NoError(t, err)
			}
			resp, body := h.authenticate(t, f, "negative", 2000, tc.mutate, signer)
			expected := 401
			// The service currently reports a signing-stage lifetime rejection as 500.
			if tc.name == "insufficient_remaining_lifetime" {
				expected = 500
			}
			require.Equal(t, expected, resp.StatusCode, body)
			require.Equal(t, before, h.relays.Load(), "invalid Telegram token reached Zitadel")
			resp, body = h.authenticate(t, f, "negative", 2000, nil, nil)
			require.Equal(t, 400, resp.StatusCode, "failed authentication must consume state: %s", body)
		})
	}

	t.Run("successful_state_cannot_be_replayed", func(t *testing.T) {
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "replay", 2001, nil, nil)
		require.Equal(t, 303, resp.StatusCode, body)
		before := h.relays.Load()
		resp, body = h.authenticate(t, f, "replay", 2001, nil, nil)
		require.Equal(t, 400, resp.StatusCode, body)
		require.Equal(t, before, h.relays.Load())
	})

	t.Run("state_is_bound_to_browser", func(t *testing.T) {
		f := h.begin(t, idp)
		f.client = h.browser()
		resp, body := h.authenticate(t, f, "cookie", 2002, nil, nil)
		require.Equal(t, 400, resp.StatusCode, body)
	})

	t.Run("missing_zitadel_cookie_cannot_relay_registration", func(t *testing.T) {
		manual := h.provider(t, "no-cookie", false, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, manual)
		u, _ := url.Parse(origin)
		f.client.Jar.SetCookies(u, []*http.Cookie{{Name: "__Host-zitadel.useragent", Value: "", Path: "/", Secure: true, MaxAge: -1}})
		resp, body := h.authenticate(t, f, "no-cookie", 2003, nil, nil)
		require.Equal(t, 502, resp.StatusCode, body)
	})

	t.Run("unknown_bot_and_duplicate_query_rejected", func(t *testing.T) {
		before := h.relays.Load()
		resp, body := request(t, h.client, "GET", origin+"/tg/login/99999", nil)
		require.Equal(t, 404, resp.StatusCode, body)
		resp, body = request(t, h.client, "GET", origin+"/tg/login/"+botID+"?authRequestID=a&authRequestID=b", nil)
		require.Equal(t, 400, resp.StatusCode, body)
		require.Equal(t, before, h.relays.Load())
	})

	t.Run("required_mfa_fails_closed", func(t *testing.T) {
		h.api(t, "POST", "/admin/v1/policies/login/second_factors", map[string]any{"type": "SECOND_FACTOR_TYPE_OTP"})
		h.setLoginPolicy(t, true)
		t.Cleanup(func() {
			h.setLoginPolicy(t, false)
			h.api(t, "DELETE", "/admin/v1/policies/login/second_factors/SECOND_FACTOR_TYPE_OTP", nil)
		})
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "mfa", 2500, nil, nil)
		require.Equal(t, 502, resp.StatusCode, body)
		require.Contains(t, h.upstreamBody.Load().(string), "/ui/login/mfa", "unexpected upstream response")
	})

	t.Run("service_restart_preserves_signing_identity", func(t *testing.T) {
		_, before := request(t, h.client, "GET", origin+"/tg/keys", nil)
		pending := h.begin(t, idp)
		h.stopApp()
		h.startApp(t, nil)
		_, after := request(t, h.client, "GET", origin+"/tg/keys", nil)
		require.JSONEq(t, before, after)
		resp, body := h.authenticate(t, pending, "restart", 3000, nil, nil)
		require.Equal(t, 400, resp.StatusCode, "pending state must not survive process restart: %s", body)
		f := h.begin(t, idp)
		resp, body = h.authenticate(t, f, "restart", 3000, nil, nil)
		require.NotEmpty(t, h.finish(t, f, resp, body))
	})

	t.Run("unverified_email_requires_zitadel_verification", func(t *testing.T) {
		h.stopApp()
		h.startApp(t, map[string]string{"synthetic_email_verified: true": "synthetic_email_verified: false"})
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "unverified", 3001, nil, nil)
		require.Equal(t, 502, resp.StatusCode, body)
		log, err := os.ReadFile(h.appLog)
		require.NoError(t, err)
		require.Contains(t, string(log), "email_verification_required")
	})

	for name, changes := range map[string]map[string]string{
		"wrong_relay_issuer": {"issuer: " + origin + "/tg": "issuer: " + origin + "/other-issuer"},
		"wrong_relay_header": {"jwt_header: x-telegram-idp-jwt": "jwt_header: x-wrong-header"},
	} {
		t.Run(name, func(t *testing.T) {
			h.stopApp()
			h.startApp(t, changes)
			f := h.begin(t, idp)
			resp, body := h.authenticate(t, f, name, 3002, nil, nil)
			require.Equal(t, 502, resp.StatusCode, body)
		})
	}

	t.Run("browser_navigation_document_completes_oidc", func(t *testing.T) {
		h.stopApp()
		h.startApp(t, nil)
		idp := h.provider(t, "browser-navigation", true, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "browser-navigation", 3004, nil, nil, "document")
		require.Equal(t, 200, resp.StatusCode, body)
		require.Empty(t, resp.Header.Get("Location"))
		require.Contains(t, resp.Header.Get("Content-Security-Policy"), "form-action 'none'")
		encoded := javascriptString(t, body, `window.location.replace\(("[^"\n]+")\)`)
		var destination string
		require.NoError(t, json.Unmarshal([]byte(encoded), &destination))
		u, err := url.Parse(destination)
		require.NoError(t, err)
		require.Equal(t, "https", u.Scheme)
		require.Equal(t, "idp.test", u.Host)
		resp, body = request(t, f.client, "GET", destination, nil)
		require.NotEmpty(t, h.finish(t, f, resp, body))
		before := h.relays.Load()
		resp, body = h.authenticate(t, f, "browser-navigation", 3004, nil, nil, "document")
		require.Equal(t, 400, resp.StatusCode, body)
		require.Equal(t, before, h.relays.Load())
	})

	t.Run("auth_rate_limit", func(t *testing.T) {
		h.stopApp()
		h.startApp(t, map[string]string{"  auth:\n    requests: 0": "  auth:\n    requests: 1\n    window: 1m"})
		f := h.begin(t, idp)
		resp, body := h.authenticate(t, f, "rate-limit", 3003, nil, nil)
		require.Equal(t, 303, resp.StatusCode, body)
		before := h.relays.Load()
		resp, body = h.authenticate(t, f, "rate-limit", 3003, nil, nil)
		require.Equal(t, 429, resp.StatusCode, body)
		require.Equal(t, before, h.relays.Load())
	})
	t.Run("prelink", h.testPrelink)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, appURL: "http://127.0.0.1:8082", keyDir: t.TempDir()}
	var err error
	h.telegram, err = app.NewSigner(app.JWTConfig{KeyID: "fake-telegram"})
	require.NoError(t, err)
	cert, roots := certificate(t)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	h.client = &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	upstream, _ := url.Parse("http://zitadel:8080")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.URL.Path != "/ui/login/login/jwt/authorize" {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		h.upstreamBody.Store(string(body))
		return nil
	}
	appUpstream, _ := url.Parse(h.appURL)
	appProxy := httputil.NewSingleHostReverseProxy(appUpstream)
	original := appProxy.Director
	appProxy.Director = func(r *http.Request) { original(r); r.Header.Set("X-Forwarded-Proto", "https") }
	mux := http.NewServeMux()
	mux.HandleFunc("/fake/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(h.telegram.JWKS())
	})
	mux.Handle("/tg/", appProxy)
	mux.HandleFunc("/internal/identity/telegram-prelink", func(w http.ResponseWriter, r *http.Request) {
		backend := h.prelink.Load()
		if backend == nil {
			http.Error(w, "prelink disabled", 503)
			return
		}
		backend.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ui/login/login/jwt/authorize" {
			h.relays.Add(1)
		}
		proxy.ServeHTTP(w, r)
	})
	listener, err := tls.Listen("tcp", ":443", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); transport.CloseIdleConnections() })
	require.Eventually(t, func() bool {
		resp, e := h.client.Get(origin + "/debug/ready")
		if e != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}, 2*time.Minute, time.Second, "Zitadel did not become ready")
	return h
}

func certificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	certPEM, err := os.ReadFile("/bootstrap/ca.crt")
	require.NoError(t, err)
	cert, err := tls.LoadX509KeyPair("/bootstrap/ca.crt", "/bootstrap/server.key")
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM))
	return cert, roots
}

func (h *harness) startApp(t *testing.T, changes map[string]string) {
	t.Helper()
	dir := t.TempDir()
	config := fmt.Sprintf(`listen: ":8082"
public_url: %s/tg
issuer: %s/tg
email_domain: telegram.invalid
synthetic_email_verified: true
state_ttl: 10m
zitadel:
  jwt_endpoint: %s/ui/login/login/jwt/authorize
  jwt_header: x-telegram-idp-jwt
  redirect_origins: [https://application.test]
jwt:
  private_key_file: %s/key.pem
  key_id: integration-relay
  ttl: 2m
  audience: %s
telegram:
  issuer: https://oauth.telegram.org
  jwks_url: %s/fake/keys
  clock_skew: 1s
proxy:
  trusted_cidrs: [127.0.0.1/32]
  secure_cookies: true
rate_limit:
  login:
    requests: 0
  auth:
    requests: 0
bots:
  - token: "123456789:integration-secret"
    name: Integration bot
    phone: true
    write: true
  - token: "987654321:other-integration-secret"
    name: Other bot
`, origin, origin, origin, h.keyDir, audience, origin)
	for before, after := range changes {
		require.Contains(t, config, before)
		config = strings.ReplaceAll(config, before, after)
	}
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(config), 0600))
	log, err := os.Create(filepath.Join(dir, "service.log"))
	require.NoError(t, err)
	h.appLog = log.Name()
	cmd := exec.Command("zitadeltg", "-config", path)
	cmd.Stdout = log
	cmd.Stderr = log
	require.NoError(t, cmd.Start())
	var stopped sync.Once
	h.stopApp = func() { stopped.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() }) }
	stop := h.stopApp
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Logf("zitadeltg log:\n%s", data)
		}
	})
	require.Eventually(t, func() bool {
		resp, e := h.client.Get(origin + "/tg/healthz")
		if e != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}, 20*time.Second, 100*time.Millisecond)
}

func (h *harness) api(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	// Cleanup callbacks run after the subtest context has been canceled.
	result, err := h.callAPI(context.Background(), method, path, body)
	require.NoError(t, err)
	return result
}

func (h *harness) callAPI(ctx context.Context, method, path string, body any) (map[string]any, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.pat)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, data)
	}
	result := map[string]any{}
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (h *harness) bootstrap() {
	t := h.t
	// Create the test tenant through the System API after the server starts.
	// This exercises live provisioning and avoids relying on FirstInstance defaults.
	data, err := os.ReadFile("/bootstrap/system.key")
	require.NoError(t, err)
	key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	require.NoError(t, err)
	h.pat, err = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "integration", "sub": "integration", "aud": origin,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}).SignedString(key)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		req, err := http.NewRequest("POST", origin+"/system/v1/instances/_search", strings.NewReader("{}"))
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+h.pat)
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}, 30*time.Second, 100*time.Millisecond, "System API did not become ready")
	tenant := h.api(t, "POST", "/system/v1/instances/_create", map[string]any{
		"instanceName": "compatibility", "firstOrgName": "integration", "customDomain": "idp.test",
		"defaultLanguage": "en",
		"machine":         map[string]any{"userName": "integration-admin", "name": "Integration admin", "personalAccessToken": map[string]any{"expirationDate": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}},
	})
	h.pat = tenant["pat"].(string)
	require.Eventually(t, func() bool {
		resp, err := h.client.Get(origin + "/.well-known/openid-configuration")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 30*time.Second, 100*time.Millisecond, "tenant projections did not become ready")
	h.api(t, "PUT", "/v2/features/instance", map[string]any{"loginV2": map[string]any{"required": false}})
	h.setLoginPolicy(t, false)
	policy := h.api(t, "GET", "/admin/v1/policies/login", nil)
	for key, path := range map[string]string{"secondFactors": "second_factors", "multiFactors": "multi_factors"} {
		if factors, ok := nested(policy, "policy", key).([]any); ok {
			for _, factor := range factors {
				h.api(t, "DELETE", "/admin/v1/policies/login/"+path+"/"+factor.(string), nil)
			}
		}
	}
	project := h.api(t, "POST", "/management/v1/projects", map[string]any{"name": "compatibility", "projectRoleCheck": false})
	organization := h.api(t, "GET", "/management/v1/orgs/me", nil)
	h.organization = nested(organization, "org", "id").(string)
	h.projectID = project["id"].(string)
	application := h.api(t, "POST", "/management/v1/projects/"+h.projectID+"/apps/oidc", map[string]any{
		"name": "test-client", "redirectUris": []string{"https://application.test/callback"}, "responseTypes": []string{"OIDC_RESPONSE_TYPE_CODE"}, "grantTypes": []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE"}, "appType": "OIDC_APP_TYPE_USER_AGENT", "authMethodType": "OIDC_AUTH_METHOD_TYPE_NONE", "loginVersion": map[string]any{"loginV1": map[string]any{}},
	})
	h.clientID = application["clientId"].(string)
}

func (h *harness) provider(t *testing.T, name string, automatic, update bool, linking, aud string) string {
	return h.providerBot(t, name, automatic, update, linking, aud, botID)
}

func (h *harness) providerBot(t *testing.T, name string, automatic, update bool, linking, aud, bot string) string {
	t.Helper()
	result := h.api(t, "POST", "/admin/v1/idps/generic_jwt", map[string]any{
		"name": name, "issuer": origin + "/tg", "jwtEndpoint": origin + "/tg/login/" + bot, "keysEndpoint": origin + "/tg/keys", "headerName": "x-telegram-idp-jwt", "audience": aud,
		"providerOptions": map[string]any{"isCreationAllowed": true, "isLinkingAllowed": true, "isAutoCreation": automatic, "isAutoUpdate": update, "autoLinking": linking},
	})
	id := result["id"].(string)
	h.api(t, "POST", "/admin/v1/policies/login/idps", map[string]any{"idpId": id})
	h.waitProvider(t, id)
	return id
}

func (h *harness) waitProvider(t *testing.T, id string) {
	t.Helper()
	// Login reads the asynchronous policy projection. Wait for provisioning
	// to become visible before creating an auth request that snapshots it.
	require.Eventually(t, func() bool {
		result, err := h.callAPI(context.Background(), "POST", "/admin/v1/policies/login/idps/_search", map[string]any{"query": map[string]any{"limit": 100}})
		if err != nil {
			return false
		}
		links, _ := result["result"].([]any)
		for _, item := range links {
			if link, ok := item.(map[string]any); ok && link["idpId"] == id {
				return true
			}
		}
		return false
	}, 90*time.Second, 100*time.Millisecond, "provider login-policy projection did not converge")
}

func (h *harness) setLoginPolicy(t *testing.T, forceMFA bool) {
	t.Helper()
	h.api(t, "PUT", "/admin/v1/policies/login", loginPolicy(forceMFA))
	require.Eventually(t, func() bool {
		result, err := h.callAPI(context.Background(), "GET", "/admin/v1/policies/login", nil)
		policy, ok := result["policy"].(map[string]any)
		actual, _ := policy["forceMfa"].(bool)
		return err == nil && ok && actual == forceMFA
	}, 90*time.Second, 100*time.Millisecond, "login-policy projection did not converge")
}

func (h *harness) human(t *testing.T, name, email string) string {
	t.Helper()
	result := h.api(t, "POST", "/management/v1/users/human/_import", map[string]any{"userName": name, "profile": map[string]any{"firstName": "Existing", "lastName": "User"}, "email": map[string]any{"email": email, "isEmailVerified": true}, "password": "Integration-Password1!", "passwordChangeRequired": false})
	return result["userId"].(string)
}

func (h *harness) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: h.client.Transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: h.client.CheckRedirect}
}

func (h *harness) begin(t *testing.T, idp string) *flow {
	t.Helper()
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	f := &flow{client: h.browser(), verifier: base64.RawURLEncoding.EncodeToString(seed), oauthState: base64.RawURLEncoding.EncodeToString(seed), idp: idp}
	digest := sha256.Sum256([]byte(f.verifier))
	q := url.Values{"client_id": {h.clientID}, "redirect_uri": {"https://application.test/callback"}, "response_type": {"code"}, "scope": {"openid profile email phone urn:zitadel:iam:org:idp:id:" + idp}, "state": {f.oauthState}, "nonce": {f.oauthState}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "prompt": {"login"}}
	resp, body := request(t, f.client, "GET", origin+"/oauth/v2/authorize?"+q.Encode(), nil)
	for i := 0; i < 12; i++ {
		if resp.StatusCode == 200 && strings.Contains(body, "const state =") {
			break
		}
		var location *url.URL
		if resp.StatusCode == 200 {
			root, err := html.Parse(strings.NewReader(body))
			require.NoError(t, err)
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "a" {
					for _, a := range n.Attr {
						if a.Key == "href" && strings.Contains(a.Val, idp) && strings.Contains(a.Val, "external") {
							location, _ = url.Parse(a.Val)
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					visit(c)
				}
			}
			visit(root)
			require.NotNil(t, location, "provider link not found: %.12000s", body)
			location = resp.Request.URL.ResolveReference(location)
		} else {
			var err error
			location, err = resp.Location()
			require.NoError(t, err, "status %d: %.2000s", resp.StatusCode, body)
		}
		require.Equal(t, "idp.test", location.Host, "unexpected redirect: %s", location)
		resp, body = request(t, f.client, "GET", location.String(), nil)
	}
	require.Equal(t, 200, resp.StatusCode, body)
	f.state = javascriptString(t, body, `const state = "([^"\n]+)"`)
	f.nonce = javascriptString(t, body, `nonce: "([^"\n]+)"`)
	f.bot = filepath.Base(resp.Request.URL.Path)
	return f
}

func (h *harness) authenticate(t *testing.T, f *flow, subject string, id int, mutate func(map[string]any), signer *app.Signer, navigation ...string) (*http.Response, string) {
	t.Helper()
	now := time.Now()
	claims := map[string]any{"iss": "https://oauth.telegram.org", "aud": f.bot, "sub": subject, "id": id, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": f.nonce, "name": "Jane Doe", "given_name": "Jane", "family_name": "Doe", "preferred_username": fmt.Sprintf("u%s-%s-%d", f.idp, f.bot, id), "phone_number": fmt.Sprintf("1555555%04d", id), "phone_number_verified": true}
	if mutate != nil {
		mutate(claims)
	}
	if signer == nil {
		signer = h.telegram
	}
	token, err := signer.Sign(claims)
	require.NoError(t, err)
	form := url.Values{"state": {f.state}, "id_token": {token}}
	if len(navigation) > 0 {
		form.Set("navigation", navigation[0])
	}
	return request(t, f.client, "POST", origin+"/tg/auth/telegram/"+f.bot, form)
}

// finish requires an actual OIDC authorization code, exchanges it with PKCE,
// and asks Zitadel's userinfo endpoint for the authenticated subject.
func (h *harness) finish(t *testing.T, f *flow, resp *http.Response, body string) string {
	t.Helper()
	for i := 0; i < 15; i++ {
		require.True(t, resp.StatusCode >= 300 && resp.StatusCode < 400, "expected login redirect, got %d: %s", resp.StatusCode, body)
		location, err := resp.Location()
		require.NoError(t, err)
		if location.Host == "application.test" {
			require.Equal(t, f.oauthState, location.Query().Get("state"))
			require.Empty(t, location.Query().Get("error"), location.String())
			code := location.Query().Get("code")
			require.NotEmpty(t, code)
			tokenResp, tokenBody := request(t, h.client, "POST", origin+"/oauth/v2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {h.clientID}, "redirect_uri": {"https://application.test/callback"}, "code": {code}, "code_verifier": {f.verifier}})
			require.Equal(t, 200, tokenResp.StatusCode, tokenBody)
			var tokens map[string]any
			require.NoError(t, json.Unmarshal([]byte(tokenBody), &tokens))
			_, keyBody := request(t, h.client, "GET", origin+"/oauth/v2/keys", nil)
			var keys struct{ Keys []struct{ Kid, N, E string } }
			require.NoError(t, json.Unmarshal([]byte(keyBody), &keys))
			idToken, err := jwt.Parse(tokens["id_token"].(string), func(token *jwt.Token) (any, error) {
				for _, key := range keys.Keys {
					if key.Kid == token.Header["kid"] {
						n, err := base64.RawURLEncoding.DecodeString(key.N)
						if err != nil {
							return nil, err
						}
						e, err := base64.RawURLEncoding.DecodeString(key.E)
						if err != nil {
							return nil, err
						}
						return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
					}
				}
				return nil, fmt.Errorf("Zitadel signing key not found")
			}, jwt.WithIssuer(origin), jwt.WithAudience(h.clientID), jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{"RS256"}))
			require.NoError(t, err)
			require.True(t, idToken.Valid)
			claims := idToken.Claims.(jwt.MapClaims)
			require.Equal(t, f.oauthState, claims["nonce"])
			req, err := http.NewRequestWithContext(context.Background(), "GET", origin+"/oidc/v1/userinfo", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
			result, err := h.client.Do(req)
			require.NoError(t, err)
			defer result.Body.Close()
			require.Equal(t, 200, result.StatusCode)
			var user map[string]any
			require.NoError(t, json.NewDecoder(result.Body).Decode(&user))
			require.NotEmpty(t, user["sub"])
			require.Equal(t, claims["sub"], user["sub"])
			return user["sub"].(string)
		}
		require.Equal(t, "idp.test", location.Host)
		resp, body = request(t, f.client, "GET", location.String(), nil)
	}
	t.Fatal("OIDC redirect loop")
	return ""
}

func request(t *testing.T, client *http.Client, method, target string, values url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if values != nil {
		body = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	require.NoError(t, err)
	if values != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		req.Header.Set("Referer", origin+"/")
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	return resp, string(data)
}

func javascriptString(t *testing.T, body, pattern string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	require.Len(t, match, 2, "missing %s in response: %.2000s", pattern, body)
	return match[1]
}

func form(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	root, err := html.Parse(strings.NewReader(body))
	require.NoError(t, err)
	values := url.Values{}
	action := ""
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		attrs := map[string]string{}
		for _, a := range n.Attr {
			attrs[a.Key] = a.Val
		}
		if n.Type == html.ElementNode && n.Data == "form" {
			require.Empty(t, action, "multiple forms")
			action = attrs["action"]
		}
		if n.Type == html.ElementNode && n.Data == "input" && attrs["name"] != "" {
			values.Set(attrs["name"], attrs["value"])
		}
		if n.Type == html.ElementNode && n.Data == "button" && strings.Contains(attrs["formaction"], "autoregisterbutton=true") {
			action = attrs["formaction"]
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(root)
	require.NotEmpty(t, action)
	return action, values
}

func nested(value map[string]any, path ...string) any {
	var current any = value
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[key]
	}
	return current
}

func loginPolicy(forceMFA bool) map[string]any {
	return map[string]any{
		"allowUsernamePassword": true, "allowRegister": true, "allowExternalIdp": true, "forceMfa": forceMFA, "passwordlessType": "PASSWORDLESS_TYPE_ALLOWED",
		"externalLoginCheckLifetime": "86400s", "passwordCheckLifetime": "86400s", "mfaInitSkipLifetime": "2592000s", "secondFactorCheckLifetime": "86400s", "multiFactorCheckLifetime": "86400s",
	}
}
