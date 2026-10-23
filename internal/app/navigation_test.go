package app

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelayNavigationDocumentAndLegacyRedirect(t *testing.T) {
	const destination = "https://zitadel.test/done?code=secret-code&state=secret-state#secret-fragment"
	for _, mode := range []string{"", "document"} {
		t.Run("mode="+mode, func(t *testing.T) {
			var logs bytes.Buffer
			srv := &Server{
				cfg:    testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt"),
				logger: slog.New(slog.NewTextHandler(&logs, nil)),
				proxyClient: fakeHTTPClient(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 307, Header: http.Header{"Location": {destination}}, Body: io.NopCloser(strings.NewReader(""))}, nil
				}),
			}
			srv.proxyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			r := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil)
			r.PostForm = url.Values{"navigation": {mode}}
			w := httptest.NewRecorder()
			require.NoError(t, srv.proxyToZitadel(w, r, "secret-jwt", "authRequestID=secret-request"))
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			if mode == "document" {
				require.Equal(t, 200, w.Code)
				require.Empty(t, w.Header().Get("Location"))
				require.Contains(t, w.Header().Get("Content-Type"), "text/html")
				require.Contains(t, w.Header().Get("Content-Security-Policy"), "form-action 'none'")
				require.Contains(t, w.Header().Get("Content-Security-Policy"), "script-src 'nonce-")
				require.Contains(t, w.Body.String(), `window.location.replace("https://zitadel.test/done?code=secret-code\u0026state=secret-state#secret-fragment")`)
				require.Contains(t, w.Body.String(), `rel="noreferrer">Continue</a>`)
			} else {
				require.Equal(t, 303, w.Code)
				require.Equal(t, destination, w.Header().Get("Location"))
			}
			require.Contains(t, logs.String(), "upstream_status=307")
			require.Contains(t, logs.String(), "destination_origin=https://zitadel.test")
			require.Contains(t, logs.String(), "destination_path=/done")
			for _, secret := range []string{"secret-code", "secret-state", "secret-fragment", "secret-jwt", "secret-request"} {
				require.NotContains(t, logs.String(), secret)
			}
		})
	}
}

func TestNavigationDocumentCannotBypassRedirectChecks(t *testing.T) {
	for _, destination := range []string{"http://zitadel.test/done", "https://attacker.test/done", "https://user@zitadel.test/done", "javascript:alert(1)"} {
		t.Run(destination, func(t *testing.T) {
			srv := &Server{
				cfg: testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt"),
				proxyClient: fakeHTTPClient(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 303, Header: http.Header{"Location": {destination}}, Body: io.NopCloser(strings.NewReader(""))}, nil
				}),
			}
			srv.proxyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			r := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil)
			r.PostForm = url.Values{"navigation": {"document"}}
			w := httptest.NewRecorder()
			require.Error(t, srv.proxyToZitadel(w, r, "fixture", ""))
			require.Equal(t, 502, w.Code)
			require.NotContains(t, w.Body.String(), "window.location.replace")
		})
	}
}

func TestNavigationPageEscapesRedirectMarkup(t *testing.T) {
	var page bytes.Buffer
	require.NoError(t, navigationPage.Execute(&page, struct{ Destination, Nonce string }{
		`https://zitadel.test/done?x=</script><script>alert(1)</script>`, "fixture",
	}))
	require.Equal(t, 1, strings.Count(page.String(), "<script"))
	require.Contains(t, page.String(), `\u003c/script\u003e`)
}

func TestTelegramAuthRejectsAmbiguousNavigationMode(t *testing.T) {
	srv := &Server{
		botsByID:   map[string]BotConfig{"123": {ID: "123"}},
		authLimits: newRequestLimiter(RateLimitBucketConfig{Requests: 10}),
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, value := range []string{"navigation=other", "navigation=document&navigation=document", "navigation="} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", strings.NewReader("state=fixture&id_token=fixture&"+value))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		srv.ServeHTTP(w, r)
		require.Equal(t, 400, w.Code)
		require.Equal(t, "invalid navigation field\n", w.Body.String())
	}
}
