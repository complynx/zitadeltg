package app

import (
	"bytes"
	"context"
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

func TestTelegramAuthProxiesJWTToZitadel(t *testing.T) {
	telegramSigner := newTestSigner(t, "telegram-key")

	var receivedQuery string
	var receivedJWT string
	zitadelCalls := 0
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "telegram.test":
			return jsonHTTPResponse(http.StatusOK, telegramSigner.JWKS()), nil
		case "zitadel.test":
			zitadelCalls++
			receivedQuery = req.URL.RawQuery
			receivedJWT = req.Header.Get("x-test-jwt")
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
	idpSigner := newTestSigner(t, "idp-key")
	srv, err := NewServer(context.Background(), cfg, idpSigner, client)
	require.NoError(t, err)

	bot := cfg.Bots[0]
	loginReq := httptest.NewRequest(http.MethodGet, "/prefix/login/"+bot.ID+"?requestID=abc&foo=bar", nil)
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
		"preferred_username":    "jane",
		"phone_number":          "15555550123",
		"phone_number_verified": true,
	})
	require.NoError(t, err)

	form := url.Values{
		"id_token": {idToken},
		"state":    {state},
	}
	req := httptest.NewRequest(http.MethodPost, "/prefix/auth/telegram/"+bot.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	require.Equal(t, http.StatusSeeOther, rr.Code, rr.Body.String())
	assert.Equal(t, "https://zitadel.test/done", rr.Header().Get("Location"))
	assert.NotContains(t, strings.Join(rr.Header().Values("Set-Cookie"), ";"), "zitadel_session")
	assert.Empty(t, rr.Header().Get("X-Internal"))
	assert.Equal(t, "foo=bar&requestID=abc", receivedQuery)
	require.NotEmpty(t, receivedJWT)
	payload := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(receivedJWT, payload, func(token *jwt.Token) (any, error) {
		return &idpSigner.private.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.Equal(t, fakeEmail(bot.ID, "telegram-sub", cfg.EmailDomain), payload["email"])
	assert.Equal(t, false, payload["email_verified"])
	assert.Equal(t, cfg.JWT.Audience, payload["aud"])
	assert.Equal(t, "15555550123", payload["phone"])
	assert.Equal(t, true, payload["phone_verified"])
	assert.Equal(t, "15555550123", payload["phone_number"])
	assert.Equal(t, true, payload["phone_number_verified"])

	replayReq := httptest.NewRequest(http.MethodPost, "/prefix/auth/telegram/"+bot.ID, strings.NewReader(form.Encode()))
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
	cfg := testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	srv := &Server{
		cfg: cfg,
		proxyClient: fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/html"}},
				Body:       io.NopCloser(strings.NewReader(`<script>window.pwned=true</script>`)),
			}, nil
		}),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/telegram/123", nil)
	err := srv.proxyToZitadel(rr, req, "jwt", "requestID=abc")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.NotContains(t, rr.Body.String(), "script")
	assert.Contains(t, rr.Header().Get("Content-Security-Policy"), "default-src 'none'")
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
