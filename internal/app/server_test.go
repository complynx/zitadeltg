package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginPageUsesRequestPrefix(t *testing.T) {
	cfg := testConfig("https://telegram.example.test/jwks", "https://accounts.example.test/idps/jwt")
	telegramSigner := newTestSigner(t, "telegram-key")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/prefix/login/123456789?requestID=abc", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := rr.Body.String()
	assert.Contains(t, body, `"/prefix/auth/telegram/123456789"`)
	assert.Contains(t, body, `"write"`)
	assert.Contains(t, body, `"phone"`)
	assert.Contains(t, rr.Header().Get("Content-Security-Policy"), "https://oauth.telegram.org")
	assert.Equal(t, "same-origin-allow-popups", rr.Header().Get("Cross-Origin-Opener-Policy"))
	require.NotEmpty(t, rr.Result().Cookies())
	assert.Less(t, len(rr.Result().Cookies()[0].Value), 100)
}

func TestNewServerAddsTimeoutToInjectedClient(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, newTestSigner(t, "telegram-key").JWKS()), nil
	})
	require.Zero(t, client.Timeout)

	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), client)
	require.NoError(t, err)
	assert.Equal(t, defaultHTTPTimeout, srv.proxyClient.Timeout)
	assert.NotNil(t, srv.proxyClient.Transport)
}

func TestReadOnlyEndpointsAdvertiseGetAndHead(t *testing.T) {
	srv := &Server{}
	for _, endpoint := range []string{"/healthz", "/keys"} {
		t.Run(endpoint, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, endpoint, nil)
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
			assert.Equal(t, "GET, HEAD", rr.Header().Get("Allow"))

			headReq := httptest.NewRequest(http.MethodHead, endpoint, nil)
			headRR := httptest.NewRecorder()
			srv.ServeHTTP(headRR, headReq)
			assert.Equal(t, http.StatusOK, headRR.Code)
			assert.Empty(t, headRR.Body.String())
		})
	}
}

func TestDebugRequestCompletionLogging(t *testing.T) {
	var logs bytes.Buffer
	srv := &Server{logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, logs.String(), "msg=\"request completed\"")
	assert.Contains(t, logs.String(), "method=GET")
	assert.Contains(t, logs.String(), "route=healthz")
	assert.Contains(t, logs.String(), "status=200")
	assert.Contains(t, logs.String(), "response_bytes=11")
	assert.Contains(t, logs.String(), "duration=")
}

func TestDebugRequestCompletionLoggingIsDisabledAtInfo(t *testing.T) {
	var logs bytes.Buffer
	srv := &Server{logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))}
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Empty(t, logs.String())
}

func TestRequestLogsDoNotEchoUntrustedPathsOrUnknownBotIDs(t *testing.T) {
	const secret = "123456789:bot-secret-marker"
	var logs bytes.Buffer
	srv := &Server{
		logger:        slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		loginLimits:   newRequestLimiter(RateLimitBucketConfig{Requests: 10, Window: time.Minute}),
		authLimits:    newRequestLimiter(RateLimitBucketConfig{Requests: 10, Window: time.Minute}),
		rateLimitLogs: newRequestLimiter(RateLimitBucketConfig{Requests: 10, Window: time.Minute}),
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/login/"+secret, nil),
		httptest.NewRequest(http.MethodPost, "/auth/telegram/"+secret, nil),
		httptest.NewRequest(http.MethodGet, "/unmatched/header.payload.signature-secret-marker", nil),
	} {
		srv.ServeHTTP(httptest.NewRecorder(), request)
	}

	assert.Contains(t, logs.String(), "route=login")
	assert.Contains(t, logs.String(), "route=telegram_auth")
	assert.Contains(t, logs.String(), "route=unmatched")
	assert.NotContains(t, logs.String(), secret)
	assert.NotContains(t, logs.String(), "signature-secret-marker")

	const querySecret = "query-secret-marker"
	srv.botsByID = map[string]BotConfig{"123": {ID: "123"}}
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/login/123?"+querySecret+"=1&"+querySecret+"=2", nil))
	assert.NotContains(t, logs.String(), querySecret)
}

func TestMaxBytesResponseWriterUnwrapsDebugMetrics(t *testing.T) {
	base := httptest.NewRecorder()
	metrics := &responseMetricsWriter{ResponseWriter: base}
	assert.Same(t, base, maxBytesResponseWriter(metrics))
	assert.Same(t, base, maxBytesResponseWriter(base))
}

func TestResponseMetricsWriterTracksFirstStatusAndActualBytes(t *testing.T) {
	base := httptest.NewRecorder()
	metrics := &responseMetricsWriter{ResponseWriter: base, status: http.StatusOK}
	metrics.WriteHeader(http.StatusTeapot)
	metrics.WriteHeader(http.StatusInternalServerError)
	n, err := metrics.Write([]byte("abc"))
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, http.StatusTeapot, metrics.status)
	assert.Equal(t, 3, metrics.bytes)
	assert.Equal(t, http.StatusTeapot, base.Code)
}

func TestTelegramAuthProxiesJWTToZitadel(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")

	var receivedQuery string
	var receivedJWT string
	var receivedCookieHeader string
	zitadelCalls := 0
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "telegram.test":
			return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
		case "zitadel.test":
			zitadelCalls++
			receivedQuery = req.URL.RawQuery
			receivedJWT = req.Header.Get("x-test-jwt")
			receivedCookieHeader = req.Header.Get("Cookie")
			return &http.Response{
				StatusCode: http.StatusFound,
				Header: http.Header{
					"Location":   []string{"/done"},
					"Set-Cookie": []string{"zitadel_session=wrong-origin"},
					"Connection": []string{"X-Internal"},
					"X-Internal": []string{"must-not-be-relayed"},
				},
				Body: io.NopCloser(strings.NewReader("")),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
	})

	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	cfg.Zitadel.JWTHeader = "x-test-jwt"
	cfg.PublicURL = "https://zitadel.test/tg"
	cfg.Issuer = cfg.PublicURL
	idpSigner := newTestSigner(t, "idp-key")
	srv, err := NewServer(context.Background(), cfg, idpSigner, client)
	require.NoError(t, err)

	bot := cfg.Bots[0]
	loginReq := httptest.NewRequest(http.MethodGet, "https://zitadel.test/prefix/login/"+bot.ID+"?requestID=abc&foo=bar", nil)
	loginRR := httptest.NewRecorder()
	srv.ServeHTTP(loginRR, loginReq)
	require.Equal(t, http.StatusOK, loginRR.Code)
	require.Len(t, loginRR.Result().Cookies(), 1)
	sessionCookie := loginRR.Result().Cookies()[0]
	state := loginStateFromHTML(t, loginRR.Body.String())
	verifiedState, err := verifyState(bot, state, time.Now(), cfg.StateTTL)
	require.NoError(t, err)
	now := time.Now()
	idToken, err := telegramSigner.Sign(map[string]any{
		"iss":                   defaultTelegramIssuer,
		"aud":                   bot.ID,
		"sub":                   "telegram-sub",
		"id":                    777000,
		"iat":                   now.Unix(),
		"exp":                   now.Add(time.Hour).Unix(),
		"nonce":                 verifiedState.Nonce,
		"name":                  "Jane Doe",
		"given_name":            "Jane",
		"family_name":           "Doe",
		"preferred_username":    "jane",
		"phone_number":          "15555550123",
		"phone_number_verified": true,
	})
	require.NoError(t, err)

	form := url.Values{
		"id_token": {idToken},
		"state":    {state},
	}
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/prefix/auth/telegram/"+bot.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	req.AddCookie(&http.Cookie{Name: defaultZitadelUserAgentCookie, Value: "encrypted-user-agent"})
	req.AddCookie(&http.Cookie{Name: "unrelated", Value: "must-not-be-forwarded"})
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	require.Equal(t, http.StatusSeeOther, rr.Code, rr.Body.String())
	assert.Equal(t, "https://zitadel.test/done", rr.Header().Get("Location"))
	assert.NotContains(t, strings.Join(rr.Header().Values("Set-Cookie"), ";"), "zitadel_session")
	assert.Empty(t, rr.Header().Get("X-Internal"))
	assert.Equal(t, "foo=bar&requestID=abc", receivedQuery)
	assert.Equal(t, defaultZitadelUserAgentCookie+"=encrypted-user-agent", receivedCookieHeader)
	assert.NotContains(t, receivedCookieHeader, sessionCookie.Name)
	assert.NotContains(t, receivedCookieHeader, "unrelated")
	require.NotEmpty(t, receivedJWT)
	payload := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(receivedJWT, payload, func(token *jwt.Token) (any, error) {
		return &idpSigner.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.Equal(t, fakeEmail(bot.ID, "telegram-sub", cfg.EmailDomain), payload["email"])
	assert.Equal(t, "Jane", payload["given_name"])
	assert.Equal(t, "Doe", payload["family_name"])
	assert.Equal(t, false, payload["email_verified"])
	assert.Equal(t, cfg.JWT.Audience, payload["aud"])
	assert.Equal(t, "15555550123", payload["phone"])
	assert.Equal(t, true, payload["phone_verified"])
	assert.Equal(t, "15555550123", payload["phone_number"])
	assert.Equal(t, true, payload["phone_number_verified"])

	replayReq := httptest.NewRequest(http.MethodPost, "https://zitadel.test/prefix/auth/telegram/"+bot.ID, strings.NewReader(form.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayReq.AddCookie(sessionCookie)
	replayRR := httptest.NewRecorder()
	srv.ServeHTTP(replayRR, replayReq)
	assert.Equal(t, http.StatusBadRequest, replayRR.Code)
	assert.Equal(t, 1, zitadelCalls)
}

func TestConcurrentLoginStatesUseOneBoundedSessionCookie(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "telegram.test":
			return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
		case "zitadel.test":
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://app.test/done"}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		default:
			return jsonHTTPResponse(http.StatusNotFound, map[string]any{}), nil
		}
	})
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), client)
	require.NoError(t, err)

	type loginFlow struct {
		state  string
		cookie *http.Cookie
	}
	flows := make([]loginFlow, 2)
	var sessionCookie *http.Cookie
	for i := range flows {
		req := httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID+"?requestID="+strconv.Itoa(i), nil)
		if sessionCookie != nil {
			req.AddCookie(sessionCookie)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Len(t, rr.Result().Cookies(), 1)
		if sessionCookie == nil {
			sessionCookie = rr.Result().Cookies()[0]
		}
		flows[i] = loginFlow{state: loginStateFromHTML(t, rr.Body.String()), cookie: rr.Result().Cookies()[0]}
	}
	require.Equal(t, flows[0].cookie.Name, flows[1].cookie.Name)
	require.Equal(t, flows[0].cookie.Value, flows[1].cookie.Value)
	require.Equal(t, "/", flows[0].cookie.Path)

	for i, flow := range flows {
		state, err := verifyState(cfg.Bots[0], flow.state, time.Now(), cfg.StateTTL)
		require.NoError(t, err)
		now := time.Now()
		idToken, err := telegramSigner.Sign(map[string]any{
			"iss":   defaultTelegramIssuer,
			"aud":   cfg.Bots[0].ID,
			"sub":   "telegram-sub-" + strconv.Itoa(i),
			"id":    777000 + i,
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
			"nonce": state.Nonce,
		})
		require.NoError(t, err)
		form := url.Values{"id_token": {idToken}, "state": {flow.state}}
		req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+cfg.Bots[0].ID, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(flow.cookie)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		require.Equal(t, http.StatusSeeOther, rr.Code, "flow %d: %s", i, rr.Body.String())
	}
}

func TestLoginRejectsDuplicateQueryParameters(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID+"?requestID=one&requestID=two", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestTelegramAuthReturnsRequestEntityTooLarge(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	body := "state=" + strings.Repeat("a", maxAuthFormBytes)
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+cfg.Bots[0].ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}

func loginStateFromHTML(t *testing.T, body string) string {
	t.Helper()
	const prefix = `const state = "`
	index := strings.Index(body, prefix)
	require.NotEqual(t, -1, index, "login page does not contain state")
	after, ok := strings.CutPrefix(body[index:], prefix)
	require.True(t, ok)
	state, _, ok := strings.Cut(after, `";`)
	require.True(t, ok, "login page state is not terminated")
	return state
}

func TestTelegramAuthRejectsMissingStateCookie(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	bot := cfg.Bots[0]
	state, err := signState(bot, "requestID=abc", "nonce-1", time.Now())
	require.NoError(t, err)
	form := url.Values{
		"id_token": {"not-used"},
		"state":    {state},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+bot.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestTelegramAuthConsumesPendingStateBeforeTokenValidation(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	loginRR := httptest.NewRecorder()
	srv.ServeHTTP(loginRR, httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID, nil))
	require.Equal(t, http.StatusOK, loginRR.Code)
	require.Len(t, loginRR.Result().Cookies(), 1)
	state := loginStateFromHTML(t, loginRR.Body.String())
	form := url.Values{"id_token": {"not-a-jwt"}, "state": {state}}

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+cfg.Bots[0].ID, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(loginRR.Result().Cookies()[0])
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr
	}

	assert.Equal(t, http.StatusUnauthorized, post().Code)
	assert.Equal(t, http.StatusBadRequest, post().Code)
}

func TestTelegramAuthRejectsCredentialsInQuery(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	bot := cfg.Bots[0]
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+bot.ID+"?id_token=leaked", strings.NewReader("state=body"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "form body")
}

func TestTelegramAuthRejectsUnsupportedContentType(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	bot := cfg.Bots[0]
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+bot.ID, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnsupportedMediaType, rr.Code)
}

func TestTelegramAuthRejectsDuplicateFormFields(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	form := url.Values{
		"state":    {"one", "two"},
		"id_token": {"token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/"+cfg.Bots[0].ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIssueZitadelJWTDoesNotForwardUnrequestedPhone(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	cfg.Bots[0].RequestPhone = false
	signer := newTestSigner(t, "idp-key")
	srv := &Server{cfg: cfg, signer: signer}
	token, err := srv.issueZitadelJWT(cfg.Bots[0], TelegramUser{
		Subject: "subject", IssuedAt: time.Now().Unix(), PhoneNumber: "15555550123",
	})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return &signer.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.NotContains(t, claims, "phone_number")
	assert.NotContains(t, claims, "phone")
}

func TestZitadelProfileNames(t *testing.T) {
	tests := []struct {
		name       string
		user       TelegramUser
		wantGiven  string
		wantFamily string
	}{
		{name: "explicit claims", user: TelegramUser{Name: "Display Name", GivenName: "Given", FamilyName: "Family"}, wantGiven: "Given", wantFamily: "Family"},
		{name: "split display name", user: TelegramUser{Name: "Daniel Joseph Drizhuk"}, wantGiven: "Daniel", wantFamily: "Joseph Drizhuk"},
		{name: "single name", user: TelegramUser{Name: "Prince"}, wantGiven: "Prince", wantFamily: "Prince"},
		{name: "username fallback", user: TelegramUser{PreferredUsername: "complynx"}, wantGiven: "complynx", wantFamily: "complynx"},
		{name: "anonymous fallback", user: TelegramUser{}, wantGiven: "Telegram", wantFamily: "Telegram"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			given, family := zitadelProfileNames(tt.user)
			assert.Equal(t, tt.wantGiven, given)
			assert.Equal(t, tt.wantFamily, family)
		})
	}
}

func TestZitadelDisplayNamePreservesExistingFallbacks(t *testing.T) {
	tests := []struct {
		name string
		user TelegramUser
		want string
	}{
		{name: "display name", user: TelegramUser{Name: "Jane Doe", PreferredUsername: "jane"}, want: "Jane Doe"},
		{name: "username", user: TelegramUser{PreferredUsername: "complynx"}, want: "complynx"},
		{name: "subject", user: TelegramUser{}, want: "Telegram user subject-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, zitadelDisplayName(tt.user, "subject-1"))
		})
	}
}

func TestIssueZitadelJWTPreservesUnverifiedPhoneStatus(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	signer := newTestSigner(t, "idp-key")
	srv := &Server{cfg: cfg, signer: signer}
	token, err := srv.issueZitadelJWT(cfg.Bots[0], TelegramUser{
		Subject: "subject", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(),
		PhoneNumber: "15555550123", PhoneNumberVerified: false,
	})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return &signer.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.Equal(t, "15555550123", claims["phone_number"])
	assert.Equal(t, false, claims["phone_number_verified"])
	assert.Equal(t, false, claims["phone_verified"])
}

func TestFakeEmailDoesNotCollideAfterSanitization(t *testing.T) {
	first := fakeEmail("123", "abc/def", "telegram.invalid")
	second := fakeEmail("123", "abc?def", "telegram.invalid")
	assert.NotEqual(t, first, second)
	assert.LessOrEqual(t, len(strings.Split(first, "@")[0]), 64)
}

func TestFakeEmailProducesValidDotAtom(t *testing.T) {
	email := fakeEmail("123", "..A...B..", "telegram.invalid")
	parsed, err := mail.ParseAddress(email)
	require.NoError(t, err)
	assert.Equal(t, email, parsed.Address)
	local, _, ok := strings.Cut(email, "@")
	require.True(t, ok)
	assert.NotContains(t, local, "..")
}

func TestFakeEmailStaysWithinMailboxLengthLimit(t *testing.T) {
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61)
	require.Len(t, domain, maxSyntheticEmailDomainBytes)
	require.True(t, validEmailDomain(domain))
	email := fakeEmail("123", strings.Repeat("subject", 30), domain)
	assert.LessOrEqual(t, len(email), 254)
}

func TestZitadelRelayRejectsNonRedirectBodies(t *testing.T) {
	const signature = "signature-secret-value"
	const relayJWT = "header.payload." + signature
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	var logs bytes.Buffer
	srv := &Server{
		cfg: cfg,
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"text/html"},
					"X-Request-Id": []string{"da30pu67r44s7385t9d0"},
				},
				Body: io.NopCloser(strings.NewReader(`<script>window.pwned=true</script>` + relayJWT)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil)
	err := srv.proxyToZitadel(rr, req, relayJWT, "requestID=abc")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Contains(t, err.Error(), "html_page")
	assert.Contains(t, err.Error(), "request_id=da30pu67r44s7385t9d0")
	assert.NotContains(t, err.Error(), "window.pwned")
	assert.NotContains(t, rr.Body.String(), "script")
	assert.Contains(t, rr.Header().Get("Content-Security-Policy"), "default-src 'none'")
	assert.Contains(t, logs.String(), "response_body=")
	assert.Contains(t, logs.String(), "window.pwned=true")
	assert.Contains(t, logs.String(), "[REDACTED]")
	assert.Contains(t, logs.String(), "jwt_unsigned=header.payload")
	assert.NotContains(t, logs.String(), signature)
}

// This is the security-relevant structure from the captured production
// ZITADEL v4.15.0 response, with session identifiers replaced and the profile
// values populated as expected after claim propagation.
const testZitadelRegistrationForm = `<html><form action="/ui/login/externaluser/option?none=true" method="POST"><input type="hidden" name="gorilla.csrf.Token" value="sensitive-csrf"><input type="hidden" name="authRequestID" value="sensitive-request"><input type="hidden" name="external-idp-config-id" value="provider-1"><input type="text" name="firstname" value="Jane" required><input type="text" name="lastname" value="Doe" required><button type="submit" formaction="/ui/login/externaluser/option?autoregisterbutton=true">Register</button></form></html>`

func addZitadelUserAgentCookie(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: defaultZitadelUserAgentCookie, Value: "encrypted-user-agent"})
}

func TestZitadelUserAgentCookieRequiresUniqueSecureSameHostCookie(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	srv := &Server{cfg: cfg}
	target, err := url.Parse(cfg.Zitadel.JWTEndpoint)
	require.NoError(t, err)
	tests := []struct {
		name      string
		request   *http.Request
		wantValue string
	}{
		{name: "missing", request: httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth", nil)},
		{name: "insecure", request: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "http://zitadel.test/auth", nil)
			addZitadelUserAgentCookie(r)
			return r
		}()},
		{name: "different host", request: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "https://idp.test/auth", nil)
			addZitadelUserAgentCookie(r)
			return r
		}()},
		{name: "duplicate", request: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth", nil)
			addZitadelUserAgentCookie(r)
			r.AddCookie(&http.Cookie{Name: defaultZitadelUserAgentCookie, Value: "second"})
			return r
		}()},
		{name: "empty", request: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth", nil)
			r.AddCookie(&http.Cookie{Name: defaultZitadelUserAgentCookie, Value: ""})
			return r
		}()},
		{name: "valid", request: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth", nil)
			addZitadelUserAgentCookie(r)
			return r
		}(), wantValue: "encrypted-user-agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookie, ok := srv.zitadelUserAgentCookie(tt.request, target)
			if tt.wantValue == "" {
				assert.False(t, ok)
				assert.Nil(t, cookie)
				return
			}
			require.True(t, ok)
			require.NotNil(t, cookie)
			assert.Equal(t, tt.wantValue, cookie.Value)
		})
	}
}

func TestZitadelRelayForwardsConfiguredUserAgentCookieName(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.Zitadel.UserAgentCookie = "zitadel.custom-useragent"
	var receivedCookieHeader string
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			receivedCookieHeader = req.Header.Get("Cookie")
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Header:     http.Header{"Content-Type": []string{"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("expected test response")),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth", nil)
	req.AddCookie(&http.Cookie{Name: defaultZitadelUserAgentCookie, Value: "default-must-not-be-forwarded"})
	req.AddCookie(&http.Cookie{Name: "zitadel.custom-useragent", Value: "encrypted-custom"})
	req.AddCookie(&http.Cookie{Name: secureSessionCookieName, Value: "session-must-not-be-forwarded"})
	require.Error(t, srv.proxyToZitadel(rr, req, "header.payload.signature", ""))
	assert.Equal(t, "zitadel.custom-useragent=encrypted-custom", receivedCookieHeader)
}

func TestZitadelRelayReturnsSameOriginRegistrationForm(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://zitadel.test/tg"
	var logs bytes.Buffer
	srv := &Server{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":            []string{"text/html; charset=utf-8"},
					"Content-Language":        []string{"en"},
					"Content-Security-Policy": []string{"default-src 'self'; form-action 'self'"},
					"Set-Cookie":              []string{"csrf=token; Path=/ui/login; Secure; HttpOnly; SameSite=Lax"},
				},
				Body: io.NopCloser(strings.NewReader(testZitadelRegistrationForm)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/tg/auth/telegram/123", nil)
	addZitadelUserAgentCookie(req)
	err := srv.proxyToZitadel(rr, req, "header.payload.signature-secret", "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, testZitadelRegistrationForm, rr.Body.String())
	assert.Equal(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Equal(t, "en", rr.Header().Get("Content-Language"))
	assert.Equal(t, "default-src 'self'; form-action 'self'", rr.Header().Get("Content-Security-Policy"))
	assert.Contains(t, rr.Header().Values("Content-Security-Policy"), registrationSecurityPolicy)
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Contains(t, strings.Join(rr.Header().Values("Set-Cookie"), ";"), "csrf=token")
	assert.Contains(t, logs.String(), "registration_relayed=true")
	assert.NotContains(t, logs.String(), "response_body")
	assert.NotContains(t, logs.String(), "jwt_unsigned")
	assert.NotContains(t, logs.String(), "sensitive-csrf")
	assert.NotContains(t, logs.String(), "sensitive-request")
	assert.NotContains(t, logs.String(), "signature-secret")
}

func TestZitadelRelayRejectsRegistrationWithoutOriginalUserAgentCookie(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://zitadel.test/tg"
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"text/html"},
					"Set-Cookie":   []string{"csrf=must-not-be-relayed"},
				},
				Body: io.NopCloser(strings.NewReader(testZitadelRegistrationForm)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/tg/auth/telegram/123", nil)
	err := srv.proxyToZitadel(rr, req, "header.payload.signature-secret", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user_agent_cookie_missing_or_invalid")
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
}

func TestZitadelRelayRejectsRegistrationWhenPublicOriginDiffers(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://alternate.test/tg"
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"text/html"},
					"Set-Cookie":   []string{"csrf=must-not-be-relayed"},
				},
				Body: io.NopCloser(strings.NewReader(testZitadelRegistrationForm)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/tg/auth/telegram/123", nil)
	addZitadelUserAgentCookie(req)
	err := srv.proxyToZitadel(rr, req, "header.payload.signature", "")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
}

func TestZitadelRelayRejectsCrossOriginRegistrationForm(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://zitadel.test/tg"
	var logs bytes.Buffer
	srv := &Server{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"text/html"},
					"Set-Cookie":   []string{"secret=must-not-be-relayed"},
				},
				Body: io.NopCloser(strings.NewReader(testZitadelRegistrationForm)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://alternate.test/auth/telegram/123", nil)
	err := srv.proxyToZitadel(rr, req, "header.payload.signature-secret", "")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
	assert.Contains(t, logs.String(), "registration_sensitive=true")
	assert.NotContains(t, logs.String(), "response_body")
	assert.NotContains(t, logs.String(), "jwt_unsigned")
	assert.NotContains(t, logs.String(), "sensitive-csrf")
	assert.NotContains(t, logs.String(), "sensitive-request")
}

func TestZitadelRelayRejectsTruncatedRegistrationForm(t *testing.T) {
	registration := testZitadelRegistrationForm + strings.Repeat("x", maxZitadelRegistrationBytes)
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://zitadel.test/tg"
	var logs bytes.Buffer
	srv := &Server{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}, "Set-Cookie": []string{"secret=must-not-be-relayed"}},
				Body:       io.NopCloser(strings.NewReader(registration)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth/telegram/123", nil)
	err := srv.proxyToZitadel(rr, req, "header.payload.signature-secret", "")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
	assert.Contains(t, logs.String(), "response_truncated=true")
	assert.Contains(t, logs.String(), "registration_sensitive=true")
	assert.NotContains(t, logs.String(), "response_body")
	assert.NotContains(t, logs.String(), "jwt_unsigned")
	assert.NotContains(t, logs.String(), "sensitive-csrf")
}

func TestZitadelRelayRejectsInsecureRegistrationRequest(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://zitadel.test/tg"
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}, "Set-Cookie": []string{"secret=must-not-be-relayed"}},
				Body:       io.NopCloser(strings.NewReader(testZitadelRegistrationForm)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://zitadel.test/auth/telegram/123", nil)
	addZitadelUserAgentCookie(req)
	err := srv.proxyToZitadel(rr, req, "header.payload.signature-secret", "")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Values("Set-Cookie"))
}

func TestZitadelRelayDoesNotLogEntityEncodedRegistration(t *testing.T) {
	entityEncoded := strings.NewReplacer(
		"externaluser", "external&#117;ser",
		"gorilla.csrf.Token", "gorilla&#46;csrf&#46;Token",
		"authRequestID", "authRequest&#73;D",
		"external-idp-config-id", "external-idp-config&#45;id",
	).Replace(testZitadelRegistrationForm)
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
	cfg.PublicURL = "https://zitadel.test/tg"
	var logs bytes.Buffer
	srv := &Server{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(strings.NewReader(entityEncoded)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://zitadel.test/auth/telegram/123", nil)
	addZitadelUserAgentCookie(req)
	require.NoError(t, srv.proxyToZitadel(rr, req, "header.payload.signature-secret", ""))
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, logs.String(), "registration_sensitive=true")
	assert.NotContains(t, logs.String(), "response_body")
	assert.NotContains(t, logs.String(), "jwt_unsigned")
	assert.NotContains(t, logs.String(), "sensitive-csrf")
}

func TestZitadelRegistrationRelayTrustsForwardedHTTPSOnlyFromConfiguredProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		wantOK     bool
	}{
		{name: "trusted proxy", remoteAddr: "10.0.0.2:443", wantOK: true},
		{name: "untrusted sender", remoteAddr: "203.0.113.4:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/ui/login/login/jwt/authorize")
			cfg.PublicURL = "https://zitadel.test/tg"
			cfg.Proxy.TrustedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
			srv := &Server{
				cfg: cfg,
				proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"text/html"}},
						Body:       io.NopCloser(strings.NewReader(testZitadelRegistrationForm)),
					}, nil
				}),
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://zitadel.test/auth/telegram/123", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Forwarded-Proto", "https")
			addZitadelUserAgentCookie(req)
			err := srv.proxyToZitadel(rr, req, "header.payload.signature-secret", "")
			if tt.wantOK {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, rr.Code)
				return
			}
			require.Error(t, err)
			assert.Equal(t, http.StatusBadGateway, rr.Code)
		})
	}
}

func TestZitadelRegistrationFormRecognitionIsStrict(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "complete form", body: testZitadelRegistrationForm, want: true},
		{name: "error code only", body: `<div title="USER-UCej2">First name is empty</div>`},
		{name: "marker in comment", body: `<!-- <input name="external-idp-config-id"> -->`},
		{name: "wrong action", body: strings.Replace(testZitadelRegistrationForm, zitadelExternalUserFormPath, "/unexpected", 1)},
		{name: "missing post method", body: strings.Replace(testZitadelRegistrationForm, ` method="POST"`, "", 1)},
		{name: "empty csrf", body: strings.Replace(testZitadelRegistrationForm, `value="sensitive-csrf"`, `value=""`, 1)},
		{name: "readonly first name", body: strings.Replace(testZitadelRegistrationForm, `name="firstname"`, `name="firstname" readonly`, 1)},
		{name: "optional first name", body: strings.Replace(testZitadelRegistrationForm, `value="Jane" required`, `value="Jane"`, 1)},
		{name: "hidden first name", body: strings.Replace(testZitadelRegistrationForm, `name="firstname"`, `name="firstname" hidden`, 1)},
		{name: "reassociated csrf", body: strings.Replace(testZitadelRegistrationForm, `name="gorilla.csrf.Token"`, `name="gorilla.csrf.Token" form="other"`, 1)},
		{name: "get formmethod", body: strings.Replace(testZitadelRegistrationForm, `type="submit"`, `type="submit" formmethod="GET"`, 1)},
		{name: "disabled fieldset", body: strings.Replace(testZitadelRegistrationForm, `<input type="text" name="firstname" value="Jane" required>`, `<fieldset disabled><input type="text" name="firstname" value="Jane" required></fieldset>`, 1)},
		{name: "duplicate required field", body: strings.Replace(testZitadelRegistrationForm, `</form>`, `<input type="text" name="firstname" value="Other" required></form>`, 1)},
		{name: "second form", body: strings.Replace(testZitadelRegistrationForm, `</html>`, `<form method="POST" action="/ui/login/externaluser/option?none=true"></form></html>`, 1)},
		{name: "external form action", body: strings.Replace(testZitadelRegistrationForm, `/ui/login/externaluser/option?autoregisterbutton=true`, `https://evil.test/register`, 1)},
		{name: "external base", body: strings.Replace(testZitadelRegistrationForm, `<html>`, `<html><base href="https://evil.test/">`, 1)},
		{name: "non html", body: testZitadelRegistrationForm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contentType := "text/html"
			if tt.name == "non html" {
				contentType = "text/plain"
			}
			assert.Equal(t, tt.want, isZitadelRegistrationForm([]byte(tt.body), contentType, http.StatusOK))
		})
	}
}

func TestPotentialZitadelRegistrationIsContentTypeAndStatusIndependent(t *testing.T) {
	assert.True(t, isPotentialZitadelRegistration([]byte(`<input name="gorilla.csrf.Token" value="secret">`)))
	assert.True(t, isPotentialZitadelRegistration([]byte(`<form action="/ui/login/externaluser/option?none=true">`)))
	entityEncoded := strings.NewReplacer(
		"externaluser", "external&#117;ser",
		"gorilla.csrf.Token", "gorilla&#46;csrf&#46;Token",
		"authRequestID", "authRequest&#73;D",
		"external-idp-config-id", "external-idp-config&#45;id",
	).Replace(testZitadelRegistrationForm)
	assert.True(t, isZitadelRegistrationForm([]byte(entityEncoded), "text/html", http.StatusOK))
	assert.True(t, isPotentialZitadelRegistration([]byte(entityEncoded)))
	assert.False(t, isPotentialZitadelRegistration([]byte(`<html>ordinary error</html>`)))
}

func TestZitadelRelayDiagnosticsAreDisabledAtInfo(t *testing.T) {
	var logs bytes.Buffer
	srv := &Server{
		cfg:    testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt"),
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(strings.NewReader("sensitive-response")),
			}, nil
		}),
	}
	err := srv.proxyToZitadel(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil), "header.payload.signature-secret", "")
	require.Error(t, err)
	assert.Empty(t, logs.String())
}

func TestZitadelRelayNonRedirectAllowsNilLogger(t *testing.T) {
	srv := &Server{
		cfg: testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt"),
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(strings.NewReader("failure")),
			}, nil
		}),
	}
	assert.NotPanics(t, func() {
		err := srv.proxyToZitadel(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil), "header.payload.signature-secret", "")
		require.Error(t, err)
	})
}

func TestZitadelRelayDiagnosticsReportBodyCompleteness(t *testing.T) {
	tests := []struct {
		name           string
		body           io.ReadCloser
		wantTruncated  bool
		wantReadFailed bool
	}{
		{name: "exact limit", body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxZitadelRegistrationBytes)))},
		{name: "over limit", body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxZitadelRegistrationBytes+1))), wantTruncated: true},
		{name: "partial read error", body: &partialErrorReadCloser{}, wantReadFailed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			srv := &Server{
				cfg:    testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt"),
				logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
				proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: tt.body}, nil
				}),
			}
			err := srv.proxyToZitadel(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil), "header.payload.signature-secret", "")
			require.Error(t, err)
			assert.Contains(t, logs.String(), "response_truncated="+strconv.FormatBool(tt.wantTruncated))
			assert.Contains(t, logs.String(), "response_read_failed="+strconv.FormatBool(tt.wantReadFailed))
			if tt.wantReadFailed {
				assert.Contains(t, err.Error(), "response_read_failed")
				assert.NotContains(t, err.Error(), "invalid_issuer")
			}
		})
	}
}

func TestUnsignedJWTExcludesSignature(t *testing.T) {
	const encoded = "header.payload.signature-secret"
	assert.Equal(t, "header.payload", unsignedJWT(encoded))
	assert.NotContains(t, unsignedJWT(encoded), "signature-secret")
	assert.Empty(t, unsignedJWT("not-a-jwt"))
}

func TestRedactJWTSignatures(t *testing.T) {
	const relayJWT = "relayhead.relaypayload.relay-signature-secret"
	const otherJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.another-signature-secret"
	const shortPayloadJWT = "eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijklmnop"
	body := []byte("relay=" + relayJWT + " other=" + otherJWT + " short=" + shortPayloadJWT)
	got := redactJWTSignatures(body, relayJWT)
	assert.Contains(t, got, "relayhead.relaypayload.[REDACTED]")
	assert.Contains(t, got, "[REDACTED_JWT]")
	assert.NotContains(t, got, "relay-signature-secret")
	assert.NotContains(t, got, "another-signature-secret")
	assert.NotContains(t, got, "abcdefghijklmnop")
}

func TestRedactJWTSignaturesRedactsExactRelayWithShortSegments(t *testing.T) {
	const relayJWT = "a.b.c"
	got := redactJWTSignatures([]byte("relay="+relayJWT), relayJWT)
	assert.Equal(t, "relay=a.b.[REDACTED]", got)
	assert.NotContains(t, got, ".c")
}

func TestClassifyZitadelResponseReturnsOnlySafeCategories(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{name: "token missing", contentType: "text/html; charset=utf-8", body: `<p class="lgn-error-message">Token not found (LOGIN-adh42)</p>`, want: "token_not_found"},
		{name: "invalid issuer", contentType: "text/html", body: `<p>invalid tokens provided: invalid issuer: secret-value</p>`, want: "invalid_issuer"},
		{name: "invalid signature", contentType: "text/html", body: `<p>invalid tokens provided: invalid signature: secret-value</p>`, want: "invalid_signature"},
		{name: "first name required", contentType: "text/html", body: `<div title="USER-UCej2">First name in profile is empty</div>`, want: "profile_first_name_required"},
		{name: "last name required", contentType: "text/html", body: `<div title="USER-4hB7d">Last name in profile is empty</div>`, want: "profile_last_name_required"},
		{name: "email verification", contentType: "text/html", body: `<form action="/ui/login/mail/verification">`, want: "email_verification_required"},
		{name: "external user action", contentType: "text/html", body: `<input name="external-idp-config-id" value="sensitive-user-value">`, want: "external_user_action_required"},
		{name: "stable error id", contentType: "text/html", body: `<p>translated message (APP-9sdp4)</p>`, want: "zitadel_error"},
		{name: "error shaped secret", contentType: "text/html", body: `<p>(SECRET-secretvalue)</p>`, want: "zitadel_error"},
		{name: "unknown html", contentType: "text/html; charset=utf-8", body: `<p>sensitive-user-value</p>`, want: "html_page"},
		{name: "unknown response", contentType: "application/json", body: `sensitive-user-value`, want: "non_redirect_response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyZitadelResponse(tt.contentType, []byte(tt.body))
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, "sensitive")
			assert.NotContains(t, got, "secret")
		})
	}
}

func TestZitadelRelayRejectsNonHTTPSRedirect(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"javascript:alert(1)"}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil)
	err := srv.proxyToZitadel(rr, req, "jwt", "requestID=abc")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Get("Location"))
}

func TestZitadelRelaySanitizesMalformedLocationError(t *testing.T) {
	const secret = "secret-request"
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://app.test/done?code=" + secret + "%zz"}},
				Body:       io.NopCloser(strings.NewReader("redirect body")),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	err := srv.proxyToZitadel(rr, httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil), "jwt", "requestID=abc")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.NotContains(t, err.Error(), secret)
	assert.Empty(t, rr.Header().Get("Location"))
}

func TestZitadelRelayRejectsUnlistedRedirectOrigin(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://phishing.test/done"}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	err := srv.proxyToZitadel(rr, httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil), "jwt", "requestID=abc")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Empty(t, rr.Header().Get("Location"))
}

func TestZitadelRelayNormalizesMethodPreservingRedirectToSeeOther(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	body := &trackingReadCloser{Reader: strings.NewReader("redirect body")}
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"https://app.test/done"}},
			Body:       body,
		}, nil
	})
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	srv := &Server{
		cfg:         cfg,
		proxyClient: client,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", strings.NewReader("id_token=secret"))
	err := srv.proxyToZitadel(rr, req, "jwt", "requestID=abc")
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "https://app.test/done", rr.Header().Get("Location"))
	assert.True(t, body.read)
	assert.True(t, body.closed)
}

func TestIssueZitadelJWTCapsSourceExpiryAndAuthTime(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	signer := newTestSigner(t, "idp-key")
	srv := &Server{cfg: cfg, signer: signer}
	now := time.Now()
	sourceExpiry := now.Add(30 * time.Second).Unix()
	token, err := srv.issueZitadelJWT(cfg.Bots[0], TelegramUser{
		Subject: "subject", IssuedAt: now.Add(10 * time.Second).Unix(), ExpiresAt: sourceExpiry,
	})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return &signer.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	expires, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.Equal(t, sourceExpiry, expires.Unix())
	assert.LessOrEqual(t, int64(claims["auth_time"].(float64)), time.Now().Unix())
}

func TestIssueZitadelJWTRejectsInsufficientRelayLifetime(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv := &Server{cfg: cfg, signer: newTestSigner(t, "idp-key")}
	_, err := srv.issueZitadelJWT(cfg.Bots[0], TelegramUser{
		Subject: "subject", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(2 * time.Second).Unix(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expires too soon")
}

func TestIssueZitadelJWTUsesConfiguredSyntheticEmailVerification(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	cfg.SyntheticEmailVerified = true
	signer := newTestSigner(t, "idp-key")
	srv := &Server{cfg: cfg, signer: signer}
	token, err := srv.issueZitadelJWT(cfg.Bots[0], TelegramUser{Subject: "subject", IssuedAt: time.Now().Unix()})
	require.NoError(t, err)

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return &signer.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	assert.Equal(t, true, claims["email_verified"])
}

func TestIssueZitadelJWTSerializedExpiryMeetsMinimumLifetime(t *testing.T) {
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	cfg.JWT.TTL = minimumConfiguredJWTTTL
	signer := newTestSigner(t, "idp-key")
	srv := &Server{cfg: cfg, signer: signer}
	before := time.Now()
	token, err := srv.issueZitadelJWT(cfg.Bots[0], TelegramUser{
		Subject: "subject", IssuedAt: before.Unix(),
	})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return &signer.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	expires, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, expires.Time.Sub(before), minimumRelayLifetime)
}

func TestLoginRateLimitUsesTrustedForwardedFor(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	cfg.Proxy.TrustedCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	cfg.RateLimit.Login = RateLimitBucketConfig{Requests: 1, Window: time.Minute}
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID+"?requestID=abc", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.10")
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		require.Equal(t, want, rr.Code, "request %d: %s", i+1, rr.Body.String())
		if want == http.StatusTooManyRequests {
			assert.NotEmpty(t, rr.Header().Get("Retry-After"))
		}
	}
}

func TestLoginStateCookieSecureByConfig(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	cfg.Proxy.SecureCookies = true
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID, nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotEmpty(t, rr.Result().Cookies())
	cookie := rr.Result().Cookies()[0]
	assert.True(t, cookie.Secure)
	assert.Equal(t, secureSessionCookieName, cookie.Name)
	assert.Equal(t, "/", cookie.Path)
}

func TestLoginSessionCookieRoundsFractionalTTLUp(t *testing.T) {
	rr := httptest.NewRecorder()
	setLoginSessionCookie(rr, "session", 1500*time.Millisecond, false)
	require.Len(t, rr.Result().Cookies(), 1)
	assert.Equal(t, 2, rr.Result().Cookies()[0].MaxAge)
}

func TestLoginFailsClosedWhenPendingStateStoreIsFull(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv, err := NewServer(context.Background(), cfg, newTestSigner(t, "idp-key"), fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
	}))
	require.NoError(t, err)
	srv.pendingStates.maxEntries = 1

	first := httptest.NewRecorder()
	srv.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID, nil))
	require.Equal(t, http.StatusOK, first.Code)

	second := httptest.NewRecorder()
	srv.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/login/"+cfg.Bots[0].ID, nil))
	assert.Equal(t, http.StatusServiceUnavailable, second.Code)
	assert.Empty(t, second.Header().Values("Set-Cookie"))
}

func TestPendingStateIsSingleUse(t *testing.T) {
	store := newPendingStateStore()
	now := time.Unix(1700000000, 0)
	store.add("session", "state", now.Add(time.Minute), now)
	assert.True(t, store.consume("session", "state", now))
	assert.False(t, store.consume("session", "state", now))
}

func TestPendingStateStoreBoundsEachSession(t *testing.T) {
	store := newPendingStateStore()
	store.maxPerSession = 2
	now := time.Unix(1700000000, 0)
	assert.Equal(t, pendingStateAdded, store.add("session", "first", now.Add(time.Minute), now))
	assert.Equal(t, pendingStateAdded, store.add("session", "second", now.Add(time.Minute), now))
	assert.Equal(t, pendingStateSessionEvicted, store.add("session", "third", now.Add(time.Minute), now))
	assert.False(t, store.consume("session", "first", now))
	assert.True(t, store.consume("session", "second", now))
	assert.True(t, store.consume("session", "third", now))
}

func TestPendingStateStoreBoundsAllSessions(t *testing.T) {
	store := newPendingStateStore()
	store.maxEntries = 2
	now := time.Unix(1700000000, 0)
	assert.Equal(t, pendingStateAdded, store.add("session-1", "first", now.Add(time.Minute), now))
	assert.Equal(t, pendingStateAdded, store.add("session-2", "second", now.Add(time.Minute), now))
	assert.Equal(t, pendingStateAtCapacity, store.add("session-3", "third", now.Add(time.Minute), now))
	assert.True(t, store.consume("session-1", "first", now))
	assert.True(t, store.consume("session-2", "second", now))
	assert.False(t, store.consume("session-3", "third", now))
}

func TestPendingStateCapacityKeepsSessionListsAttached(t *testing.T) {
	store := newPendingStateStore()
	store.maxEntries = 2
	now := time.Unix(1700000000, 0)
	assert.Equal(t, pendingStateAdded, store.add("session-a", "old-a", now.Add(time.Minute), now))
	assert.Equal(t, pendingStateAdded, store.add("session-b", "state-b", now.Add(time.Minute), now))
	assert.Equal(t, pendingStateAtCapacity, store.add("session-a", "new-a", now.Add(time.Minute), now))

	assert.Len(t, store.entries, 2)
	assert.Equal(t, len(store.entries), store.globalOrder.Len())
	assert.Equal(t, len(store.entries), pendingSessionEntryCount(store))
	assert.True(t, store.consume("session-a", "old-a", now))
	assert.True(t, store.consume("session-b", "state-b", now))
	assert.False(t, store.consume("session-a", "new-a", now))
}

func pendingSessionEntryCount(store *pendingStateStore) int {
	total := 0
	for _, order := range store.sessionOrders {
		total += order.Len()
	}
	return total
}

type trackingReadCloser struct {
	io.Reader
	read   bool
	closed bool
}

type partialErrorReadCloser struct {
	sent bool
}

func (r *partialErrorReadCloser) Read(data []byte) (int, error) {
	if r.sent {
		return 0, errors.New("test read failure")
	}
	r.sent = true
	return copy(data, "invalid issuer in partial response"), nil
}

func (*partialErrorReadCloser) Close() error { return nil }

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.read = true
	return r.Reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestRequestLimiterBoundsDistinctClients(t *testing.T) {
	now := time.Unix(1700000000, 0)
	limiter := newRequestLimiter(RateLimitBucketConfig{Requests: 1, Window: time.Minute})
	limiter.maxEntries = 2

	allowed, _, capacityLimited := limiter.allow("client-1", now)
	assert.True(t, allowed)
	assert.False(t, capacityLimited)
	allowed, _, capacityLimited = limiter.allow("client-2", now)
	assert.True(t, allowed)
	assert.False(t, capacityLimited)
	allowed, retryAfter, capacityLimited := limiter.allow("client-3", now)
	assert.False(t, allowed)
	assert.Positive(t, retryAfter)
	assert.True(t, capacityLimited)
	assert.Len(t, limiter.entries, 2)
	assert.Contains(t, limiter.entries, "client-1")
	assert.NotContains(t, limiter.entries, "client-3")

	allowed, _, capacityLimited = limiter.allow("client-3", now.Add(6*time.Minute))
	assert.True(t, allowed)
	assert.False(t, capacityLimited)
	assert.LessOrEqual(t, len(limiter.entries), 2)
}

func TestRequestLimiterRecoversCapacityAtWindowReset(t *testing.T) {
	now := time.Unix(1700000000, 0)
	limiter := newRequestLimiter(RateLimitBucketConfig{Requests: 1, Window: time.Minute})
	limiter.maxEntries = 2
	allowed, _, _ := limiter.allow("client-1", now)
	assert.True(t, allowed)
	allowed, _, _ = limiter.allow("client-2", now)
	assert.True(t, allowed)

	allowed, _, capacityLimited := limiter.allow("client-3", now.Add(time.Minute))
	assert.True(t, allowed)
	assert.False(t, capacityLimited)
	assert.Contains(t, limiter.entries, "client-3")
	assert.LessOrEqual(t, len(limiter.entries), 2)
}

func TestRequestLimiterCapacityRetryUsesEarliestReset(t *testing.T) {
	base := time.Unix(1700000000, 0)
	limiter := newRequestLimiter(RateLimitBucketConfig{Requests: 1, Window: time.Hour})
	limiter.maxEntries = 2
	allowed, _, _ := limiter.allow("client-1", base)
	require.True(t, allowed)
	allowed, _, _ = limiter.allow("client-2", base.Add(30*time.Minute))
	require.True(t, allowed)

	allowed, retryAfter, capacityLimited := limiter.allow("client-3", base.Add(45*time.Minute))
	assert.False(t, allowed)
	assert.True(t, capacityLimited)
	assert.Equal(t, 15*60, retryAfter)
}

func TestRequestLimiterCapacityRecoveryUsesResetOrder(t *testing.T) {
	base := time.Unix(1700000000, 0)
	limiter := newRequestLimiter(RateLimitBucketConfig{Requests: 1, Window: time.Hour})
	limiter.maxEntries = maxRateLimitCleanupBatch + 2

	for _, key := range []string{"expired-1", "expired-2"} {
		allowed, _, _ := limiter.allow(key, base)
		require.True(t, allowed)
	}
	for i := range maxRateLimitCleanupBatch {
		allowed, _, _ := limiter.allow("fresh-"+strconv.Itoa(i), base.Add(30*time.Minute))
		require.True(t, allowed)
	}
	// Touch the soon-to-expire entries so they move behind all fresh entries in
	// LRU order without changing their fixed-window reset time.
	for _, key := range []string{"expired-1", "expired-2"} {
		allowed, _, _ := limiter.allow(key, base.Add(45*time.Minute))
		require.False(t, allowed)
	}
	require.Equal(t, "fresh-0", limiter.order.Front().Value)

	allowed, _, capacityLimited := limiter.allow("new-client", base.Add(time.Hour))
	assert.True(t, allowed)
	assert.False(t, capacityLimited)
	assert.Contains(t, limiter.entries, "new-client")
	assert.NotContains(t, limiter.entries, "expired-1")
	assert.LessOrEqual(t, len(limiter.entries), limiter.maxEntries)
}

func TestRateLimitDenialLogsAreBounded(t *testing.T) {
	var logs bytes.Buffer
	srv := &Server{
		logger:        slog.New(slog.NewTextHandler(&logs, nil)),
		rateLimitLogs: newRequestLimiter(RateLimitBucketConfig{Requests: 5, Window: time.Minute}),
	}
	limiter := newRequestLimiter(RateLimitBucketConfig{Requests: 1, Window: time.Minute})
	req := httptest.NewRequest(http.MethodGet, "/login/123", nil)
	req.RemoteAddr = "203.0.113.4:1234"
	assert.True(t, srv.allowRequest(httptest.NewRecorder(), req, limiter, "login", "123"))
	for range 100 {
		rr := httptest.NewRecorder()
		assert.False(t, srv.allowRequest(rr, req, limiter, "login", "123"))
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	}
	assert.Equal(t, 5, strings.Count(logs.String(), "request rate limit exceeded"))
}

func TestRequestLogsExcludeUntrustedHeaderValues(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil)
	req.Header.Set("X-Request-ID", "secret-request-id-marker")
	logger.Warn("request", requestAttrs(req, slog.String("bot_id", "123"))...)
	assert.NotContains(t, logs.String(), "secret-request-id-marker")

	logs.Reset()
	req.Header.Set("X-Request-ID", "01234567-abcd-abcd-abcd-0123456789ab")
	logger.Warn("request", requestAttrs(req, slog.String("bot_id", "123"))...)
	assert.Contains(t, logs.String(), "01234567-abcd-abcd-abcd-0123456789ab")
}

func newTestSigner(t *testing.T, keyID string) *Signer {
	t.Helper()
	signer, err := NewSigner(JWTConfig{KeyID: keyID})
	require.NoError(t, err)
	return signer
}

func testConfig(jwksURL string, zitadelEndpoint string) Config {
	return Config{
		Listen:      ":0",
		PublicURL:   "https://idp.example.test",
		Issuer:      "https://idp.example.test",
		EmailDomain: "telegram.invalid",
		StateTTL:    10 * time.Minute,
		Zitadel: ZitadelConfig{
			JWTEndpoint:     zitadelEndpoint,
			JWTHeader:       "x-zitadel-jwt",
			UserAgentCookie: defaultZitadelUserAgentCookie,
			RedirectOrigins: []string{"https://app.test"},
		},
		JWT: JWTConfig{
			TTL:      2 * time.Minute,
			KeyID:    "idp-key",
			Audience: zitadelEndpoint,
		},
		Telegram: TelegramConfig{
			Issuer:       defaultTelegramIssuer,
			JWKSURL:      jwksURL,
			JWKSCacheTTL: time.Hour,
			ClockSkew:    30 * time.Second,
		},
		Bots: []BotConfig{
			{
				ID:           "123456789",
				Secret:       "secret",
				Name:         "Main Bot",
				RequestWrite: true,
				RequestPhone: true,
				Lang:         "en",
			},
		},
	}
}
