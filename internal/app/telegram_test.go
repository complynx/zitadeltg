package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTelegramValidationErrorCategory(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: jwt.ErrTokenMalformed, want: "malformed"},
		{err: fmt.Errorf("wrapped: %w", jwt.ErrTokenSignatureInvalid), want: "invalid_signature"},
		{err: jwt.ErrTokenExpired, want: "expired"},
		{err: jwt.ErrTokenNotValidYet, want: "not_valid_yet"},
		{err: jwt.ErrTokenInvalidIssuer, want: "invalid_issuer"},
		{err: jwt.ErrTokenInvalidAudience, want: "invalid_audience"},
		{err: jwt.ErrTokenRequiredClaimMissing, want: "required_claim_missing"},
		{err: jwt.ErrTokenUsedBeforeIssued, want: "issued_in_future"},
		{err: jwt.ErrTokenUnverifiable, want: "unverifiable"},
		{err: jwt.ErrTokenInvalidClaims, want: "invalid_claims"},
		{err: errTelegramTokenInvalid, want: "invalid_token"},
		{err: errTelegramSubjectMissing, want: "subject_missing"},
		{err: errTelegramUserIDMissing, want: "user_id_missing"},
		{err: errTelegramUserIDInvalid, want: "user_id_invalid"},
		{err: errTelegramIssuedAtMissing, want: "issued_at_missing"},
		{err: errTelegramNonceMismatch, want: "nonce_mismatch"},
		{err: context.Canceled, want: "canceled"},
		{err: context.DeadlineExceeded, want: "timeout"},
		{err: errors.New("sensitive details"), want: "invalid_token"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, telegramValidationErrorCategory(tt.err))
	}
}

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
		"given_name":            "Jane",
		"family_name":           "Doe",
		"preferred_username":    "janedoe",
		"picture":               "https://example.com/p.jpg",
		"phone_number":          "15555550123",
		"phone_number_verified": true,
	})
	require.NoError(t, err)

	user, err := validator.Validate(context.Background(), token, "123456789", "nonce-1")
	require.NoError(t, err)
	assert.Equal(t, "tg-subject", user.Subject)
	assert.Equal(t, "987654321", user.TelegramID)
	assert.Equal(t, "Jane", user.GivenName)
	assert.Equal(t, "Doe", user.FamilyName)
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
		"id":    987654321,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": "nonce-1",
	})
	require.NoError(t, err)
	_, err = validator.Validate(context.Background(), token, "123456789", "nonce-2")
	require.ErrorIs(t, err, errTelegramNonceMismatch)
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
		"id": 987654321, "exp": time.Now().Add(time.Hour).Unix(), "nonce": "nonce-1",
	})
	require.NoError(t, err)
	_, err = validator.Validate(context.Background(), token, "123456789", "nonce-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issued-at")
}

func TestTelegramValidatorRejectsMissingOrInvalidUserID(t *testing.T) {
	signer := newTestSigner(t, "telegram-key")
	client := fakeHTTPClient(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, signer.JWKS()), nil
	})
	validator, err := NewTelegramValidator(context.Background(), TelegramConfig{
		Issuer: defaultTelegramIssuer, JWKSURL: "https://telegram.test/jwks",
		JWKSCacheTTL: time.Hour, ClockSkew: 30 * time.Second,
	}, client)
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      any
		wantErr error
	}{
		{name: "missing", wantErr: errTelegramUserIDMissing},
		{name: "fractional", id: 1.5, wantErr: errTelegramUserIDInvalid},
		{name: "zero", id: 0, wantErr: errTelegramUserIDInvalid},
		{name: "negative", id: -1, wantErr: errTelegramUserIDInvalid},
		{name: "string", id: "987654321", wantErr: errTelegramUserIDInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			claims := map[string]any{
				"iss": defaultTelegramIssuer, "aud": "123456789", "sub": "tg-subject",
				"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "nonce-1",
			}
			if tt.id != nil {
				claims["id"] = tt.id
			}
			token, err := signer.Sign(claims)
			require.NoError(t, err)
			_, err = validator.Validate(context.Background(), token, "123456789", "nonce-1")
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestCanonicalTelegramID(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{name: "smallest", raw: "1"},
		{name: "Telegram upper boundary", raw: "4503599627370495"},
		{name: "missing", wantErr: errTelegramUserIDMissing},
		{name: "zero", raw: "0", wantErr: errTelegramUserIDInvalid},
		{name: "negative", raw: "-1", wantErr: errTelegramUserIDInvalid},
		{name: "leading plus", raw: "+1", wantErr: errTelegramUserIDInvalid},
		{name: "leading zero", raw: "01", wantErr: errTelegramUserIDInvalid},
		{name: "fractional", raw: "1.0", wantErr: errTelegramUserIDInvalid},
		{name: "exponent", raw: "1e3", wantErr: errTelegramUserIDInvalid},
		{name: "above Telegram upper boundary", raw: "4503599627370496", wantErr: errTelegramUserIDInvalid},
		{name: "max int64", raw: "9223372036854775807", wantErr: errTelegramUserIDInvalid},
		{name: "int64 overflow", raw: "9223372036854775808", wantErr: errTelegramUserIDInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalTelegramID(tt.raw)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.raw, got)
		})
	}
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
