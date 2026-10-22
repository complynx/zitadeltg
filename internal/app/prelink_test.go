package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type prelinkFlow struct {
	server        *Server
	telegram, idp *Signer
	config        Config
	backend       func(*http.Request, map[string]any, int) (*http.Response, error)
	calls, relays int
	bodies        []string
	relayJWT      string
	logs          bytes.Buffer
}

func newPrelinkFlow(t *testing.T) *prelinkFlow {
	t.Helper()
	f := &prelinkFlow{telegram: newTestSigner(t, "telegram-key"), idp: newTestSigner(t, "provider-key")}
	f.config = testConfig("https://telegram.test/jwks", "https://zitadel.test/idps/jwt")
	f.config.SyntheticEmailVerified = true
	f.config.Zitadel.RedirectOrigins = []string{"https://zitadel.test"}
	f.config.Bots[0].Prelink = PrelinkConfig{
		Endpoint: "https://zinusya.test" + prelinkPath, Audience: "zinusya-prelink",
		OrganizationID: "org", ProviderID: "fixture-idp",
		ServiceBearer: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
	}
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "telegram.test":
			return jsonHTTPResponse(200, f.telegram.JWKS()), nil
		case "zinusya.test":
			f.calls++
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, prelinkPath, req.URL.Path)
			assert.Equal(t, "Bearer "+f.config.Bots[0].Prelink.ServiceBearer, req.Header.Get("Authorization"))
			assert.Empty(t, req.Header.Get("Cookie"))
			assert.Empty(t, req.Header.Get(f.config.Zitadel.JWTHeader))
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			f.bodies = append(f.bodies, string(raw))
			receipt, err := f.matchingReceipt(raw)
			if err != nil {
				return nil, err
			}
			if f.backend != nil {
				return f.backend(req, receipt, f.calls)
			}
			return jsonHTTPResponse(200, receipt), nil
		case "zitadel.test":
			f.relays++
			f.relayJWT = req.Header.Get(f.config.Zitadel.JWTHeader)
			assert.Empty(t, req.Header.Get("Authorization"))
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"/done"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			return nil, errors.New("unexpected destination")
		}
	})
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	origin, err := url.Parse("https://zinusya.test")
	require.NoError(t, err)
	jar.SetCookies(origin, []*http.Cookie{{Name: "private_cookie", Value: "must-not-leak", Secure: true}})
	client.Jar = jar
	client.Timeout = time.Minute
	f.server, err = NewServer(t.Context(), f.config, f.idp, client, slog.New(slog.NewTextHandler(&f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	require.NoError(t, err)
	return f
}

func (f *prelinkFlow) matchingReceipt(raw []byte) (map[string]any, error) {
	var request struct {
		Assertion string `json:"assertion"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return nil, errors.New("fixture malformed request")
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(request.Assertion, claims, func(*jwt.Token) (any, error) { return &f.idp.private.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(f.config.Issuer), jwt.WithAudience("zinusya-prelink"))
	if err != nil || !parsed.Valid {
		return nil, errors.New("fixture invalid provider proof")
	}
	if claims["urn:zinusya:purpose"] != "telegram-prelink" || claims["urn:zitadeltg:telegram:user_id"] != "777000" ||
		claims["urn:zitadeltg:telegram:subject"] != "actual-opaque-not-777000" || claims["sub"] != "telegram:123456789:actual-opaque-not-777000" {
		return nil, errors.New("fixture proof scope mismatch")
	}
	issued, expires := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if expires-issued > 60 || expires <= issued {
		return nil, errors.New("fixture invalid proof lifetime")
	}
	digest := sha256.Sum256([]byte(request.Assertion))
	return map[string]any{
		"operation_id": "11111111-1111-4111-8111-111111111111", "user_id": "22222222-2222-4222-8222-222222222222",
		"subject": "fixture-iam-subject", "state": "completed", "issuer": f.config.Issuer,
		"assertion_sha256": hex.EncodeToString(digest[:]), "assertion_jti": claims["jti"],
		"bot_id": int64(123456789), "telegram_user_id": int64(777000), "external_subject": "actual-opaque-not-777000",
		"organization": "org", "provider_id": "fixture-idp", "expires_at": time.Unix(expires, 0).UTC(),
	}, nil
}

func (f *prelinkFlow) callback(t *testing.T, alter func(map[string]any), ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	bot := f.config.Bots[0]
	return f.callbackBot(t, bot, alter, ctx)
}

func (f *prelinkFlow) callbackBot(t *testing.T, bot BotConfig, alter func(map[string]any), ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	login := httptest.NewRecorder()
	f.server.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "https://idp.example.test/login/"+bot.ID+"?requestID=fixture", nil))
	require.Equal(t, 200, login.Code, login.Body.String())
	cookies := login.Result().Cookies()
	require.Len(t, cookies, 1)
	state := loginStateFromHTML(t, login.Body.String())
	verified, err := verifyState(bot, state, time.Now(), f.config.StateTTL)
	require.NoError(t, err)
	now := time.Now()
	claims := map[string]any{"iss": defaultTelegramIssuer, "aud": bot.ID, "sub": "actual-opaque-not-777000", "id": 777000,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": verified.Nonce, "given_name": "Alice", "family_name": "Fixture"}
	if alter != nil {
		alter(claims)
	}
	token, err := f.telegram.Sign(claims)
	require.NoError(t, err)
	body := url.Values{"id_token": []string{token}, "state": []string{state}}
	request := httptest.NewRequest(http.MethodPost, "https://idp.example.test/auth/telegram/"+bot.ID, strings.NewReader(body.Encode())).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	f.server.ServeHTTP(response, request)
	return response
}

func TestPrelinkCompletesBeforeDistinctIAMRelay(t *testing.T) {
	f := newPrelinkFlow(t)
	response := f.callback(t, nil, t.Context())
	require.Equal(t, 303, response.Code, response.Body.String())
	require.Equal(t, 1, f.calls)
	require.Equal(t, 1, f.relays)
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(f.relayJWT, claims, func(*jwt.Token) (any, error) { return &f.idp.private.PublicKey, nil }, jwt.WithAudience(f.config.JWT.Audience))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.NotContains(t, claims, "urn:zinusya:purpose")
	require.NotContains(t, f.logs.String(), f.config.Bots[0].Prelink.ServiceBearer)
	require.NotContains(t, f.logs.String(), f.bodies[0])
}

func TestPrelinkLostCompletionReplyRetriesIdenticalProof(t *testing.T) {
	f := newPrelinkFlow(t)
	f.backend = func(_ *http.Request, receipt map[string]any, attempt int) (*http.Response, error) {
		if attempt == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return jsonHTTPResponse(200, receipt), nil
	}
	response := f.callback(t, nil, t.Context())
	require.Equal(t, 303, response.Code, response.Body.String())
	require.Equal(t, 2, f.calls)
	require.Equal(t, f.bodies[0], f.bodies[1])
	require.Equal(t, 1, f.relays)
}

func TestPrelinkFailureWithholdsIAMRelay(t *testing.T) {
	for _, tc := range []struct {
		name             string
		status, attempts int
	}{
		{"invalid service key", 401, 1}, {"revoked", 403, 1}, {"conflicting binding", 409, 1},
		{"redirect", 302, 1}, {"IAM outage", 503, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrelinkFlow(t)
			f.backend = func(_ *http.Request, _ map[string]any, _ int) (*http.Response, error) {
				response := jsonHTTPResponse(tc.status, map[string]string{"error": "not accepted"})
				response.Header.Set("Location", "https://other.test/steal")
				return response, nil
			}
			response := f.callback(t, nil, t.Context())
			require.Contains(t, []int{403, 503}, response.Code, response.Body.String())
			require.Equal(t, tc.attempts, f.calls)
			require.Zero(t, f.relays)
			require.Empty(t, f.relayJWT)
			for _, body := range f.bodies {
				require.Equal(t, f.bodies[0], body)
			}
		})
	}
}

func TestPrelinkMismatchedReceiptNeverRelays(t *testing.T) {
	cases := map[string]any{
		"state": "pending", "issuer": "https://other.test", "assertion_jti": "other", "assertion_sha256": "bad-hash",
		"bot_id": 123, "telegram_user_id": 456, "external_subject": "777000", "organization": "other", "provider_id": "other",
		"expires_at": time.Now().Add(time.Hour), "operation_id": "not-a-uuid", "user_id": "00000000-0000-0000-0000-000000000000", "subject": "",
	}
	for field, value := range cases {
		t.Run(field, func(t *testing.T) {
			f := newPrelinkFlow(t)
			f.backend = func(_ *http.Request, receipt map[string]any, _ int) (*http.Response, error) {
				receipt[field] = value
				return jsonHTTPResponse(200, receipt), nil
			}
			response := f.callback(t, nil, t.Context())
			require.Equal(t, 503, response.Code, response.Body.String())
			require.Equal(t, 1, f.calls)
			require.Zero(t, f.relays)
		})
	}
}

func TestPrelinkMalformedReceiptNeverRelays(t *testing.T) {
	for _, kind := range []string{"malformed", "duplicate", "case alias", "extra value", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			f := newPrelinkFlow(t)
			f.backend = func(_ *http.Request, receipt map[string]any, _ int) (*http.Response, error) {
				raw, _ := json.Marshal(receipt)
				switch kind {
				case "malformed":
					raw = []byte(`{`)
				case "duplicate":
					raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"state":"completed"}`)
				case "case alias":
					raw = []byte(strings.Replace(string(raw), `"state":`, `"State":`, 1))
				case "extra value":
					raw = append(raw, []byte(` {}`)...)
				case "oversized":
					raw = bytes.Repeat([]byte{'x'}, prelinkResponseLimit+1)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
			}
			response := f.callback(t, nil, t.Context())
			require.Equal(t, 503, response.Code, response.Body.String())
			require.Zero(t, f.relays)
		})
	}
}

func TestPrelinkInvalidTelegramProofNeverCallsBackend(t *testing.T) {
	for _, field := range []string{"aud", "iss", "nonce"} {
		t.Run(field, func(t *testing.T) {
			f := newPrelinkFlow(t)
			response := f.callback(t, func(claims map[string]any) { claims[field] = "invalid" }, t.Context())
			require.Equal(t, 401, response.Code, response.Body.String())
			require.Zero(t, f.calls)
			require.Zero(t, f.relays)
		})
	}
}

func TestPrelinkCancellationStopsRetriesAndRelay(t *testing.T) {
	f := newPrelinkFlow(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.backend = func(_ *http.Request, _ map[string]any, _ int) (*http.Response, error) {
		cancel()
		return nil, io.ErrUnexpectedEOF
	}
	response := f.callback(t, nil, ctx)
	require.Equal(t, 503, response.Code, response.Body.String())
	require.Equal(t, 1, f.calls)
	require.Zero(t, f.relays)
}

func TestPrelinkRedirectCannotForwardCredentials(t *testing.T) {
	f := newPrelinkFlow(t)
	transport := f.server.prelinkClient.Transport
	redirectRequests := 0
	f.server.prelinkClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/redirect-target" {
			redirectRequests++
			return jsonHTTPResponse(200, nil), nil
		}
		return transport.RoundTrip(req)
	})
	f.backend = func(_ *http.Request, _ map[string]any, _ int) (*http.Response, error) {
		// Same-host redirects would retain Authorization if followed.
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://zinusya.test/redirect-target"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	response := f.callback(t, nil, t.Context())
	require.Equal(t, 403, response.Code)
	require.Equal(t, 1, f.calls)
	require.Zero(t, redirectRequests)
	require.Zero(t, f.relays)
	require.Nil(t, f.server.prelinkClient.Jar)
	require.Equal(t, prelinkRequestTimeout, f.server.prelinkClient.Timeout)
}

func TestPrelinkCanceledCompletionNeverRelays(t *testing.T) {
	f := newPrelinkFlow(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.backend = func(_ *http.Request, receipt map[string]any, _ int) (*http.Response, error) {
		cancel()
		return jsonHTTPResponse(200, receipt), nil
	}
	response := f.callback(t, nil, ctx)
	require.Equal(t, 503, response.Code)
	require.Equal(t, 1, f.calls)
	require.Zero(t, f.relays)
}

func TestPrelinkRejectsUnusableProofAndUnboundedProfileBeforeHook(t *testing.T) {
	for name, alter := range map[string]func(map[string]any){
		"too little lifetime":       func(c map[string]any) { c["exp"] = time.Now().Add(2 * time.Second).Unix() },
		"oversized given name":      func(c map[string]any) { c["given_name"] = strings.Repeat("x", prelinkFieldLimit+1) },
		"oversized family name":     func(c map[string]any) { c["family_name"] = strings.Repeat("x", prelinkFieldLimit+1) },
		"oversized username":        func(c map[string]any) { c["preferred_username"] = strings.Repeat("x", prelinkFieldLimit+1) },
		"profile control character": func(c map[string]any) { c["given_name"] = "Alice\nFixture" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPrelinkFlow(t)
			response := f.callback(t, alter, t.Context())
			require.Equal(t, 403, response.Code, response.Body.String())
			require.Zero(t, f.calls)
			require.Zero(t, f.relays)
		})
	}
}

func TestPrelinkDoesNotLogIdentityOnIAMFailure(t *testing.T) {
	f := newPrelinkFlow(t)
	f.server.proxyClient = fakeHTTPClient(func(*http.Request) (*http.Response, error) {
		return jsonHTTPResponse(500, map[string]string{"identity": "personal-upstream-marker"}), nil
	})
	response := f.callback(t, nil, t.Context())
	require.Equal(t, 502, response.Code)
	require.NotContains(t, f.logs.String(), "telegram_jwt_unsigned")
	require.NotContains(t, f.logs.String(), "jwt_unsigned")
	require.NotContains(t, f.logs.String(), "personal-upstream-marker")
}

func TestPrelinkEmailPolicyDoesNotChangeOtherBots(t *testing.T) {
	f := newPrelinkFlow(t)
	cfg := f.config
	cfg.EmailDomain = "example.com"
	cfg.SyntheticEmailVerified = false
	other := cfg.Bots[0]
	other.ID = "987654321"
	other.Prelink = PrelinkConfig{}
	cfg.Bots = append(append([]BotConfig(nil), cfg.Bots...), other)
	var err error
	f.server, err = NewServer(t.Context(), cfg, f.idp, f.server.proxyClient, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	for _, tc := range []struct {
		bot      BotConfig
		domain   string
		verified bool
	}{
		{cfg.Bots[0], "telegram.invalid", true},
		{other, "example.com", false},
	} {
		response := f.callbackBot(t, tc.bot, nil, t.Context())
		require.Equal(t, 303, response.Code, response.Body.String())
		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(f.relayJWT, claims, func(*jwt.Token) (any, error) { return &f.idp.private.PublicKey, nil }, jwt.WithAudience(cfg.JWT.Audience))
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		require.Equal(t, telegramIdentityEmail(tc.bot.ID, "777000", tc.domain), claims["email"])
		require.Equal(t, tc.verified, claims["email_verified"])
	}
	require.Equal(t, 1, f.calls)
	require.Equal(t, 2, f.relays)
}
