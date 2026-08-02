package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type TelegramUser struct {
	Subject             string
	Name                string
	PreferredUsername   string
	Picture             string
	PhoneNumber         string
	PhoneNumberVerified bool
	IssuedAt            int64
	ExpiresAt           int64
}

type TelegramValidator struct {
	cfg     TelegramConfig
	keyfunc keyfunc.Keyfunc
}

type telegramClaims struct {
	Name                string `json:"name,omitempty"`
	PreferredUsername   string `json:"preferred_username,omitempty"`
	Picture             string `json:"picture,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

const (
	defaultHTTPTimeout          = 10 * time.Second
	maxRemoteResponseHeaderSize = 64 << 10
	maxJWKSBodyBytes            = 1 << 20
)

type boundedJWKSTransport struct {
	next http.RoundTripper
}

func (t boundedJWKSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return resp, nil
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes+1))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read Telegram JWKS response: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close Telegram JWKS response: %w", closeErr)
	}
	if len(body) > maxJWKSBodyBytes {
		return nil, errors.New("Telegram JWKS response is too large")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func boundedDefaultTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = maxRemoteResponseHeaderSize
	return transport
}

func withDefaultHTTPTimeout(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Transport: boundedDefaultTransport(), Timeout: defaultHTTPTimeout}
	}
	if client.Timeout > 0 && client.Transport != nil {
		return client
	}
	// Do not copy the http.Client itself: it contains internal synchronization
	// state once used. Preserve its configuration in a fresh bounded client.
	transport := client.Transport
	if transport == nil {
		transport = boundedDefaultTransport()
	}
	bounded := &http.Client{
		Transport:     transport,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
	if bounded.Timeout <= 0 {
		bounded.Timeout = defaultHTTPTimeout
	}
	return bounded
}

func jwksHTTPClient(client *http.Client) *http.Client {
	client = withDefaultHTTPTimeout(client)
	return &http.Client{
		Transport: boundedJWKSTransport{next: client.Transport},
		Timeout:   client.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func NewTelegramValidator(ctx context.Context, cfg TelegramConfig, httpClient *http.Client, loggers ...*slog.Logger) (*TelegramValidator, error) {
	httpClient = jwksHTTPClient(httpClient)
	logger := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	noErrorFirstRequest := false
	k, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{cfg.JWKSURL}, keyfunc.Override{
		Client:                    httpClient,
		RefreshInterval:           cfg.JWKSCacheTTL,
		NoErrorReturnFirstHTTPReq: &noErrorFirstRequest,
		RefreshErrorHandlerFunc: func(u string) func(context.Context, error) {
			return func(ctx context.Context, err error) {
				logger.ErrorContext(ctx, "refresh Telegram JWKS failed",
					slog.String("jwks_url", redactURLQuery(u)),
					slog.String("cause", safeRemoteCause(err)),
				)
			}
		},
	})
	if err != nil {
		return nil, sanitizedRemoteError("initialize Telegram JWKS", cfg.JWKSURL, err)
	}
	return &TelegramValidator{
		cfg:     cfg,
		keyfunc: k,
	}, nil
}

func redactURLQuery(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	if parsed.RawQuery != "" {
		parsed.RawQuery = "redacted"
	}
	parsed.Fragment = ""
	return parsed.String()
}

func sanitizedRemoteError(operation string, rawURL string, err error) error {
	return fmt.Errorf("%s %s failed (%s)", operation, redactURLQuery(rawURL), safeRemoteCause(err))
}

func safeRemoteCause(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case err == nil:
		return "unknown"
	default:
		return fmt.Sprintf("%T", err)
	}
}

func (v *TelegramValidator) Validate(ctx context.Context, token string, botID string, nonce string) (TelegramUser, error) {
	claims := &telegramClaims{}
	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		v.keyfunc.KeyfuncCtx(ctx),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(botID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(v.cfg.ClockSkew),
		jwt.WithJSONNumber(),
	)
	if err != nil {
		return TelegramUser{}, err
	}
	if !parsed.Valid {
		return TelegramUser{}, errors.New("Telegram token is invalid")
	}
	if claims.Subject == "" {
		return TelegramUser{}, errors.New("Telegram subject is missing")
	}
	if claims.IssuedAt == nil {
		return TelegramUser{}, errors.New("Telegram issued-at time is missing")
	}
	if nonce == "" || claims.Nonce != nonce {
		return TelegramUser{}, errors.New("Telegram nonce does not match")
	}

	return TelegramUser{
		Subject:             claims.Subject,
		Name:                claims.Name,
		PreferredUsername:   claims.PreferredUsername,
		Picture:             claims.Picture,
		PhoneNumber:         claims.PhoneNumber,
		PhoneNumberVerified: claims.PhoneNumberVerified,
		IssuedAt:            numericDateUnix(claims.IssuedAt),
		ExpiresAt:           numericDateUnix(claims.ExpiresAt),
	}, nil
}

func numericDateUnix(date *jwt.NumericDate) int64 {
	if date == nil {
		return 0
	}
	return date.Unix()
}
