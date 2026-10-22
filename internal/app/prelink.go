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
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	prelinkLifetime       = time.Minute
	prelinkSkew           = 5 * time.Second
	prelinkTimeout        = 8 * time.Second
	prelinkRequestTimeout = 3 * time.Second
	prelinkRetryDelay     = 150 * time.Millisecond
	prelinkAttempts       = 3
	prelinkResponseLimit  = 16 << 10
	prelinkFieldLimit     = 200
	prelinkPath           = "/internal/identity/telegram-prelink"
)

var (
	errPrelinkDenied      = errors.New("Telegram account linking denied")
	errPrelinkUnavailable = errors.New("Telegram account linking unavailable")
	errPrelinkReceipt     = errors.New("Telegram account linking receipt mismatch")
)

// PrelinkConfig is per bot so other provider clients retain their existing flow.
// Only a configured backend can acknowledge a completed identity link.
type PrelinkConfig struct {
	Endpoint       string `yaml:"endpoint"`
	Audience       string `yaml:"audience"`
	ServiceBearer  string `yaml:"service_bearer"`
	OrganizationID string `yaml:"organization_id"`
	ProviderID     string `yaml:"provider_id"`
}

func validatePrelink(p PrelinkConfig, cfg Config, botSecret string) error {
	if p == (PrelinkConfig{}) {
		return nil
	}
	endpoint, err := url.Parse(p.Endpoint)
	if err != nil || len(p.Endpoint) > 2048 || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		endpoint.Opaque != "" || endpoint.Path != prelinkPath || endpoint.RawPath != "" {
		return errors.New("prelink requires the exact HTTPS backend endpoint")
	}
	for _, value := range []string{p.Audience, p.OrganizationID, p.ProviderID} {
		if !prelinkText(value) {
			return errors.New("prelink audience, organization and provider required")
		}
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(p.ServiceBearer)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != p.ServiceBearer || p.ServiceBearer == botSecret ||
		p.Audience == cfg.JWT.Audience {
		return errors.New("prelink requires dedicated key and audience")
	}
	return nil
}

func prelinkText(value string) bool {
	return value != "" && len(value) <= prelinkFieldLimit && utf8.ValidString(value) &&
		!strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

type prelinkIntent struct {
	Assertion, JTI, BotID, UserID, Opaque, Issuer, Digest string
	ExpiresAt                                             time.Time
}

func (s *Server) prelinkIntent(bot BotConfig, user TelegramUser, now time.Time) (prelinkIntent, error) {
	numeric, err := canonicalTelegramID(user.TelegramID)
	if err != nil || !prelinkText(user.Subject) || len("telegram:"+bot.ID+":"+user.Subject) > prelinkFieldLimit {
		return prelinkIntent{}, errPrelinkDenied
	}
	botID, err := canonicalTelegramID(bot.ID)
	if err != nil || botID != bot.ID {
		return prelinkIntent{}, errPrelinkDenied
	}
	issued := now.Unix()
	expires := now.Add(prelinkLifetime).Unix()
	if user.ExpiresAt <= 0 {
		return prelinkIntent{}, errPrelinkDenied
	}
	expires = min(expires, user.ExpiresAt)
	if time.Unix(expires, 0).Sub(now) < minimumRelayLifetime {
		return prelinkIntent{}, errPrelinkDenied
	}
	jti, err := randomID()
	if err != nil {
		return prelinkIntent{}, errPrelinkUnavailable
	}
	given, family := zitadelProfileNames(user)
	for _, value := range []string{given, family, user.PreferredUsername} {
		if len(value) > prelinkFieldLimit || !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
			return prelinkIntent{}, errPrelinkDenied
		}
	}
	claims := map[string]any{
		"iss": s.cfg.Issuer, "aud": bot.Prelink.Audience, "sub": "telegram:" + bot.ID + ":" + user.Subject,
		"jti": jti, "iat": issued, "nbf": now.Add(-prelinkSkew).Unix(), "exp": expires,
		"urn:zinusya:purpose": "telegram-prelink", "urn:zitadeltg:telegram:bot_id": bot.ID,
		"urn:zitadeltg:telegram:user_id": numeric, "urn:zitadeltg:telegram:subject": user.Subject,
		"email": telegramIdentityEmail(bot.ID, numeric, "telegram.invalid"), "email_verified": true,
		"given_name": given, "family_name": family, "preferred_username": user.PreferredUsername,
	}
	assertion, err := s.signer.Sign(claims)
	if err != nil {
		return prelinkIntent{}, errPrelinkUnavailable
	}
	digest := sha256.Sum256([]byte(assertion))
	return prelinkIntent{Assertion: assertion, JTI: jti, BotID: bot.ID, UserID: numeric, Opaque: user.Subject,
		Issuer: s.cfg.Issuer, Digest: hex.EncodeToString(digest[:]), ExpiresAt: time.Unix(expires, 0).UTC()}, nil
}

// prelinkTelegram runs only after Telegram signature/nonce verification. Retries
// retain one compact assertion; a new browser login may reconcile with a new JTI.
func (s *Server) prelinkTelegram(ctx context.Context, bot BotConfig, user TelegramUser) error {
	if bot.Prelink == (PrelinkConfig{}) {
		return nil
	}
	intent, err := s.prelinkIntent(bot, user, time.Now())
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"assertion": intent.Assertion})
	if err != nil {
		return errPrelinkUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, prelinkTimeout)
	defer cancel()
	ctx, expire := context.WithDeadline(ctx, intent.ExpiresAt)
	defer expire()
	for attempt := 0; attempt < prelinkAttempts; attempt++ {
		retry, err := s.sendPrelink(ctx, bot.Prelink, intent, body)
		if err == nil {
			return nil
		}
		if !retry || attempt+1 == prelinkAttempts {
			return err
		}
		timer := time.NewTimer(prelinkRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errPrelinkUnavailable
		case <-timer.C:
		}
	}
	return errPrelinkUnavailable
}

func (s *Server) sendPrelink(ctx context.Context, cfg PrelinkConfig, intent prelinkIntent, body []byte) (bool, error) {
	if ctx.Err() != nil {
		return false, errPrelinkUnavailable
	}
	if !intent.ExpiresAt.After(time.Now()) {
		return false, errPrelinkDenied
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false, errPrelinkUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+cfg.ServiceBearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.prelinkClient.Do(request)
	if err != nil {
		return true, errPrelinkUnavailable
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, prelinkResponseLimit+1))
	if readErr != nil {
		return true, errPrelinkUnavailable
	}
	if len(raw) > prelinkResponseLimit {
		return false, errPrelinkReceipt
	}
	if ctx.Err() != nil {
		return false, errPrelinkUnavailable
	}
	if response.StatusCode >= 500 {
		return true, errPrelinkUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return false, errPrelinkDenied
	}
	receipt, err := decodePrelinkReceipt(raw)
	if err != nil {
		return false, errPrelinkReceipt
	}
	if !receipt.matches(cfg, intent, time.Now()) {
		return false, errPrelinkReceipt
	}
	return false, nil
}

type prelinkReceipt struct {
	OperationID     string    `json:"operation_id"`
	AssertionSHA256 string    `json:"assertion_sha256"`
	State           string    `json:"state"`
	Issuer          string    `json:"issuer"`
	AssertionJTI    string    `json:"assertion_jti"`
	BotID           int64     `json:"bot_id"`
	TelegramUserID  int64     `json:"telegram_user_id"`
	ExternalSubject string    `json:"external_subject"`
	UserID          string    `json:"user_id"`
	Subject         string    `json:"subject"`
	Organization    string    `json:"organization"`
	ProviderID      string    `json:"provider_id"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (r prelinkReceipt) matches(cfg PrelinkConfig, intent prelinkIntent, now time.Time) bool {
	return r.State == "completed" && validPrelinkUUID(r.OperationID) && validPrelinkUUID(r.UserID) && prelinkText(r.Subject) &&
		r.AssertionSHA256 == intent.Digest && r.Issuer == intent.Issuer && r.AssertionJTI == intent.JTI &&
		strconv.FormatInt(r.BotID, 10) == intent.BotID && strconv.FormatInt(r.TelegramUserID, 10) == intent.UserID &&
		r.ExternalSubject == intent.Opaque && r.Organization == cfg.OrganizationID && r.ProviderID == cfg.ProviderID &&
		r.ExpiresAt.Equal(intent.ExpiresAt) && r.ExpiresAt.After(now)
}

func validPrelinkUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(raw) == 16 && !bytes.Equal(raw, make([]byte, 16))
}

// Decode exact receipt fields; duplicates and case aliases cannot select values.
func decodePrelinkReceipt(raw []byte) (prelinkReceipt, error) {
	var receipt prelinkReceipt
	if !utf8.Valid(raw) {
		return receipt, errPrelinkReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return receipt, errPrelinkReceipt
	}
	allowed := []string{"operation_id", "assertion_sha256", "state", "issuer", "assertion_jti", "bot_id",
		"telegram_user_id", "external_subject", "user_id", "subject", "organization", "provider_id", "expires_at"}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return receipt, errPrelinkReceipt
		}
		name, ok := token.(string)
		if !ok || seen[name] || !slices.Contains(allowed, name) {
			return receipt, errPrelinkReceipt
		}
		seen[name] = true
		var ignored json.RawMessage
		if decoder.Decode(&ignored) != nil {
			return receipt, errPrelinkReceipt
		}
	}
	if _, err = decoder.Token(); err != nil {
		return receipt, errPrelinkReceipt
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return receipt, errPrelinkReceipt
	}
	if len(seen) != len(allowed) || json.Unmarshal(raw, &receipt) != nil {
		return receipt, errPrelinkReceipt
	}
	return receipt, nil
}
