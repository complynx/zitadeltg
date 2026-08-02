package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTelegramValidatorValidatesSignedIDToken(t *testing.T) {
	signer := newTestSigner(t, "telegram-key")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, signer.JWKS()), nil
	})

	validator, err := NewTelegramValidator(context.Background(), TelegramConfig{
		Issuer:       defaultTelegramIssuer,
		JWKSURL:      "https://telegram.test/jwks",
		JWKSCacheTTL: time.Hour,
		ClockSkew:    30 * time.Second,
	}, client)
	require.NoError(t, err)

	now := time.Now()
	token, err := signer.Sign(map[string]any{
		"iss":                   defaultTelegramIssuer,
		"aud":                   "123456789",
		"sub":                   "tg-subject",
		"id":                    987654321,
		"iat":                   now.Unix(),
		"exp":                   now.Add(time.Hour).Unix(),
		"nonce":                 "nonce-1",
		"name":                  "Jane Doe",
		"preferred_username":    "janedoe",
		"picture":               "https://example.com/p.jpg",
		"phone_number":          "15555550123",
		"phone_number_verified": true,
	})
	require.NoError(t, err)

	user, err := validator.Validate(context.Background(), token, "123456789", "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, "tg-subject", user.Subject)
	assert.Equal(t, "15555550123", user.PhoneNumber)
	assert.True(t, user.PhoneNumberVerified)
}

func TestTelegramValidatorRejectsWrongNonce(t *testing.T) {
	signer := newTestSigner(t, "telegram-key")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, signer.JWKS()), nil
	})

	validator, err := NewTelegramValidator(context.Background(), TelegramConfig{
		Issuer:       defaultTelegramIssuer,
		JWKSURL:      "https://telegram.test/jwks",
		JWKSCacheTTL: time.Hour,
		ClockSkew:    30 * time.Second,
	}, client)
	require.NoError(t, err)

	now := time.Now()
	token, err := signer.Sign(map[string]any{
		"iss":   defaultTelegramIssuer,
		"aud":   "123456789",
		"sub":   "tg-subject",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": "nonce-1",
	})
	require.NoError(t, err)
	_, err = validator.Validate(context.Background(), token, "123456789", "nonce-2")
	require.Error(t, err)
}

func TestTelegramValidatorRejectsMissingIssuedAt(t *testing.T) {
	signer := newTestSigner(t, "telegram-key")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, signer.JWKS()), nil
	})
	validator, err := NewTelegramValidator(context.Background(), TelegramConfig{
		Issuer: defaultTelegramIssuer, JWKSURL: "https://telegram.test/jwks",
		JWKSCacheTTL: time.Hour, ClockSkew: 30 * time.Second,
	}, client)
	require.NoError(t, err)
	token, err := signer.Sign(map[string]any{
		"iss": defaultTelegramIssuer, "aud": "123456789", "sub": "tg-subject",
		"exp": time.Now().Add(time.Hour).Unix(), "nonce": "nonce-1",
	})
	require.NoError(t, err)
	_, err = validator.Validate(context.Background(), token, "123456789", "nonce-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issued-at")
}

func TestTelegramValidatorUsesSubjectRegardlessOfCustomID(t *testing.T) {
	signer := newTestSigner(t, "telegram-key")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, signer.JWKS()), nil
	})
	validator, err := NewTelegramValidator(context.Background(), TelegramConfig{
		Issuer: defaultTelegramIssuer, JWKSURL: "https://telegram.test/jwks",
		JWKSCacheTTL: time.Hour, ClockSkew: 30 * time.Second,
	}, client)
	require.NoError(t, err)
	now := time.Now()
	token, err := signer.Sign(map[string]any{
		"iss": defaultTelegramIssuer, "aud": "123456789", "sub": "tg-subject",
		"id": 1.5, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "nonce-1",
	})
	require.NoError(t, err)
	user, err := validator.Validate(context.Background(), token, "123456789", "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, "tg-subject", user.Subject)
}

func TestRedactURLQuery(t *testing.T) {
	assert.Equal(t, "https://telegram.test/keys?redacted", redactURLQuery("https://telegram.test/keys?token=secret"))
	assert.Equal(t, "https://telegram.test/keys", redactURLQuery("https://telegram.test/keys"))
}

func TestSanitizedRemoteErrorDoesNotExposeQueryOrWrappedMessage(t *testing.T) {
	err := sanitizedRemoteError(
		"call remote",
		"https://example.test/callback?requestID=secret-request",
		errors.New("request failed for https://example.test/callback?requestID=secret-request"),
	)
	assert.NotContains(t, err.Error(), "secret-request")
	assert.NotContains(t, err.Error(), "request failed for")
	assert.Contains(t, err.Error(), "https://example.test/callback?redacted")
}

func TestWithDefaultHTTPTimeoutDoesNotCopyClientState(t *testing.T) {
	transport := &trackingTransport{fn: func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	}}
	client := &http.Client{Transport: transport}

	bounded := withDefaultHTTPTimeout(client)
	assert.NotSame(t, client, bounded)
	assert.Equal(t, defaultHTTPTimeout, bounded.Timeout)
	assert.Equal(t, client.Transport, bounded.Transport)

	explicit := &http.Client{Timeout: time.Minute}
	boundedDefault := withDefaultHTTPTimeout(explicit)
	assert.NotSame(t, explicit, boundedDefault)
	assert.Equal(t, time.Minute, boundedDefault.Timeout)
	defaultTransport, ok := boundedDefault.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, int64(maxRemoteResponseHeaderSize), defaultTransport.MaxResponseHeaderBytes)

	explicit.Transport = transport
	assert.Same(t, explicit, withDefaultHTTPTimeout(explicit))
}

func TestJWKSHTTPClientRejectsRedirectsAndCookies(t *testing.T) {
	client := &http.Client{
		Transport: &trackingTransport{fn: func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("unused")
		}},
		Jar:     &testCookieJar{},
		Timeout: time.Minute,
	}
	jwksClient := jwksHTTPClient(client)
	boundedTransport, ok := jwksClient.Transport.(boundedJWKSTransport)
	require.True(t, ok)
	assert.Same(t, client.Transport, boundedTransport.next)
	assert.Equal(t, client.Timeout, jwksClient.Timeout)
	assert.Nil(t, jwksClient.Jar)
	err := jwksClient.CheckRedirect(&http.Request{}, nil)
	assert.ErrorIs(t, err, http.ErrUseLastResponse)
}

func TestJWKSHTTPClientRejectsOversizedBody(t *testing.T) {
	client := jwksHTTPClient(fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxJWKSBodyBytes+1))),
		}, nil
	}))
	resp, err := client.Get("https://telegram.test/jwks")
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "too large")
}

type testCookieJar struct{}

func (*testCookieJar) SetCookies(*url.URL, []*http.Cookie) {}

func (*testCookieJar) Cookies(*url.URL) []*http.Cookie { return nil }

type trackingTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.fn(req)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func fakeHTTPClient(fn func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{Transport: roundTripFunc(fn)}
}

func jsonHTTPResponse(status int, value any) *http.Response {
	var b strings.Builder
	if err := json.NewEncoder(&b).Encode(value); err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(b.String())),
	}
}
