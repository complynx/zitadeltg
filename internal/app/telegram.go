package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type TelegramUser struct {
	Subject             string
	TelegramID          string
	Name                string
	GivenName           string
	FamilyName          string
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
	ID                  any    `json:"id,omitempty"`
	Name                string `json:"name,omitempty"`
	GivenName           string `json:"given_name,omitempty"`
	FamilyName          string `json:"family_name,omitempty"`
	PreferredUsername   string `json:"preferred_username,omitempty"`
	Picture             string `json:"picture,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

var (
	errTelegramTokenInvalid    = errors.New("Telegram token is invalid")
	errTelegramSubjectMissing  = errors.New("Telegram subject is missing")
	errTelegramUserIDMissing   = errors.New("Telegram user ID is missing")
	errTelegramUserIDInvalid   = errors.New("Telegram user ID is invalid")
	errTelegramIssuedAtMissing = errors.New("Telegram issued-at time is missing")
	errTelegramNonceMismatch   = errors.New("Telegram nonce does not match")
)

const (
	defaultHTTPTimeout          = 10 * time.Second
	maxRemoteResponseHeaderSize = 64 << 10
	maxJWKSBodyBytes            = 1 << 20
	maxTelegramNumericID        = int64(1<<52 - 1)
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
	logger.DebugContext(ctx, "Telegram JWKS initialized",
		slog.String("jwks_url", redactURLQuery(cfg.JWKSURL)),
		slog.Duration("refresh_interval", cfg.JWKSCacheTTL),
	)
	return &TelegramValidator{
		cfg:     cfg,
		keyfunc: k,
	}, nil
}

func telegramValidationErrorCategory(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "invalid_signature"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "not_valid_yet"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "invalid_issuer"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "invalid_audience"
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return "required_claim_missing"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return "issued_in_future"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return "unverifiable"
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		return "invalid_claims"
	case errors.Is(err, errTelegramTokenInvalid):
		return "invalid_token"
	case errors.Is(err, errTelegramSubjectMissing):
		return "subject_missing"
	case errors.Is(err, errTelegramUserIDMissing):
		return "user_id_missing"
	case errors.Is(err, errTelegramUserIDInvalid):
		return "user_id_invalid"
	case errors.Is(err, errTelegramIssuedAtMissing):
		return "issued_at_missing"
	case errors.Is(err, errTelegramNonceMismatch):
		return "nonce_mismatch"
	default:
		return "invalid_token"
	}
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
		return TelegramUser{}, errTelegramTokenInvalid
	}
	if claims.Subject == "" {
		return TelegramUser{}, errTelegramSubjectMissing
	}
	telegramID, err := telegramIDFromClaim(claims.ID)
	if err != nil {
		return TelegramUser{}, err
	}
	if claims.IssuedAt == nil {
		return TelegramUser{}, errTelegramIssuedAtMissing
	}
	if nonce == "" || claims.Nonce != nonce {
		return TelegramUser{}, errTelegramNonceMismatch
	}

	return TelegramUser{
		Subject:             claims.Subject,
		TelegramID:          telegramID,
		Name:                claims.Name,
		GivenName:           claims.GivenName,
		FamilyName:          claims.FamilyName,
		PreferredUsername:   claims.PreferredUsername,
		Picture:             claims.Picture,
		PhoneNumber:         claims.PhoneNumber,
		PhoneNumberVerified: claims.PhoneNumberVerified,
		IssuedAt:            numericDateUnix(claims.IssuedAt),
		ExpiresAt:           numericDateUnix(claims.ExpiresAt),
	}, nil
}

func telegramIDFromClaim(value any) (string, error) {
	if value == nil {
		return "", errTelegramUserIDMissing
	}
	number, ok := value.(json.Number)
	if !ok {
		return "", errTelegramUserIDInvalid
	}
	return canonicalTelegramID(number.String())
}

func canonicalTelegramID(raw string) (string, error) {
	if raw == "" {
		return "", errTelegramUserIDMissing
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 || id > maxTelegramNumericID || strconv.FormatInt(id, 10) != raw {
		return "", errTelegramUserIDInvalid
	}
	return raw, nil
}

func numericDateUnix(date *jwt.NumericDate) int64 {
	if date == nil {
		return 0
	}
	return date.Unix()
}
