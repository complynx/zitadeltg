//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const hookAudience = "integration-telegram-prelink"

// This fixture represents the application's canonical-account owner. All IAM
// provisioning and link read-back use real Zitadel APIs, without email auto-linking.
type prelinkBackend struct {
	h                *harness
	provider, bearer string
	mode             atomic.Value
	requests         atomic.Int64
	lastError        atomic.Value
	mu               sync.Mutex
	accounts         map[int]string
	assertions       []string
}

func (h *harness) testPrelink(t *testing.T) {
	provider := h.provider(t, "prelinked", false, false, "AUTO_LINKING_OPTION_UNSPECIFIED", audience)
	backend := &prelinkBackend{h: h, provider: provider, bearer: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), accounts: map[int]string{}}
	backend.mode.Store("normal")
	h.prelink.Store(backend)
	config := map[string]string{"    name: Integration bot": fmt.Sprintf(`    name: Integration bot
    prelink:
      endpoint: %s/internal/identity/telegram-prelink
      audience: %s
      service_bearer: %s
      organization_id: %s
      provider_id: %s`, origin, hookAudience, backend.bearer, h.organization, provider)}
	h.stopApp()
	h.startApp(t, config)

	login := func(t *testing.T, subject string, id int) string {
		t.Helper()
		f := h.begin(t, provider)
		resp, body := h.authenticate(t, f, subject, id, nil, nil)
		require.Equal(t, 303, resp.StatusCode, "prelinked user must not see registration: %s; backend: %v", body, backend.lastError.Load())
		return h.finish(t, f, resp, body)
	}
	t.Run("provider_first_and_sequential_login", func(t *testing.T) {
		first := login(t, "opaque-provider-first", 4001)
		require.Equal(t, first, login(t, "opaque-provider-first", 4001))
		require.Equal(t, first, backend.account(4001))
	})
	t.Run("bot_first", func(t *testing.T) {
		expected, err := backend.ensureAccount(t.Context(), 4002)
		require.NoError(t, err)
		require.Equal(t, expected, login(t, "opaque-bot-first", 4002))
	})
	t.Run("lost_completion_reply_retries_identical_assertion", func(t *testing.T) {
		backend.mode.Store("lose-reply")
		before := backend.requests.Load()
		require.NotEmpty(t, login(t, "opaque-lost-reply", 4003))
		require.Equal(t, before+2, backend.requests.Load())
		backend.mu.Lock()
		last := append([]string(nil), backend.assertions[len(backend.assertions)-2:]...)
		backend.mu.Unlock()
		require.Equal(t, last[0], last[1])
		backend.mode.Store("normal")
	})
	t.Run("concurrent_bot_and_provider_first_entry", func(t *testing.T) {
		done := make(chan struct {
			subject string
			err     error
		}, 1)
		f := h.begin(t, provider)
		go func() {
			sub, err := backend.ensureAccount(t.Context(), 4004)
			done <- struct {
				subject string
				err     error
			}{sub, err}
		}()
		resp, body := h.authenticate(t, f, "opaque-concurrent", 4004, nil, nil)
		actual := h.finish(t, f, resp, body)
		result := <-done
		require.NoError(t, result.err)
		require.Equal(t, result.subject, actual)
	})
	for i, mode := range []string{"denied", "conflict", "outage", "wrong-receipt", "timeout"} {
		t.Run(mode+"_withholds_iam_relay", func(t *testing.T) {
			backend.mode.Store(mode)
			defer backend.mode.Store("normal")
			before := h.relays.Load()
			f := h.begin(t, provider)
			resp, body := h.authenticate(t, f, "opaque-"+mode, 4100+i, nil, nil)
			require.Contains(t, []int{403, 503}, resp.StatusCode, body)
			require.Equal(t, before, h.relays.Load())
		})
	}
	for _, field := range []string{"iss", "aud", "nonce", "exp"} {
		t.Run("invalid_telegram_"+field+"_never_calls_hook", func(t *testing.T) {
			before := backend.requests.Load()
			relays := h.relays.Load()
			f := h.begin(t, provider)
			resp, body := h.authenticate(t, f, "opaque-invalid", 4200, func(c map[string]any) {
				if field == "exp" {
					c[field] = time.Now().Add(-time.Minute).Unix()
				} else {
					c[field] = "wrong"
				}
			}, nil)
			require.Equal(t, 401, resp.StatusCode, body)
			require.Equal(t, before, backend.requests.Load())
			require.Equal(t, relays, h.relays.Load())
		})
	}
	t.Run("completed_login_survives_service_restart", func(t *testing.T) {
		expected := login(t, "opaque-restart", 4005)
		h.stopApp()
		h.startApp(t, config)
		require.Equal(t, expected, login(t, "opaque-restart", 4005))
	})
}

func (b *prelinkBackend) account(id int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accounts[id]
}

func (b *prelinkBackend) ensureAccount(ctx context.Context, id int) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ensureAccountLocked(ctx, id)
}

func (b *prelinkBackend) ensureAccountLocked(ctx context.Context, id int) (string, error) {
	if sub := b.accounts[id]; sub != "" {
		return sub, nil
	}
	result, err := b.h.callAPI(ctx, "POST", "/management/v1/users/human/_import", map[string]any{
		"userName": fmt.Sprintf("prelink-%d", id), "profile": map[string]any{"firstName": "Canonical", "lastName": "Account"},
		"email":    map[string]any{"email": fmt.Sprintf("tg+%s+%d@telegram.invalid", botID, id), "isEmailVerified": true},
		"password": "Integration-Password1!", "passwordChangeRequired": false,
	})
	if err != nil {
		return "", err
	}
	sub, ok := result["userId"].(string)
	if !ok || sub == "" {
		return "", errors.New("missing IAM subject")
	}
	b.accounts[id] = sub
	return sub, nil
}

func (b *prelinkBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.requests.Add(1)
	if r.Method != "POST" || r.Header.Get("Cookie") != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+b.bearer)) != 1 {
		http.Error(w, "unauthorized", 401)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		http.Error(w, "body", 400)
		return
	}
	var envelope struct {
		Assertion string `json:"assertion"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		http.Error(w, "JSON", 400)
		return
	}
	parsed, err := jwt.Parse(envelope.Assertion, func(token *jwt.Token) (any, error) {
		return fixtureSigningKey(r.Context(), b.h.client, origin+"/tg/keys", token)
	},
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(origin+"/tg"), jwt.WithAudience(hookAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid {
		b.lastError.Store(fmt.Sprintf("assertion verification: %v", err))
		http.Error(w, "assertion", 403)
		return
	}
	claims := parsed.Claims.(jwt.MapClaims)
	numeric, ok := claims["urn:zitadeltg:telegram:user_id"].(string)
	if !ok {
		http.Error(w, "numeric ID", 403)
		return
	}
	id, err := strconv.Atoi(numeric)
	opaque, ok := claims["urn:zitadeltg:telegram:subject"].(string)
	expiry, expiryErr := claims.GetExpirationTime()
	issued, issuedErr := claims.GetIssuedAt()
	if err != nil || id <= 0 || !ok || opaque == "" || expiryErr != nil || issuedErr != nil || expiry == nil || issued == nil || expiry.Sub(issued.Time) > time.Minute ||
		claims["urn:zitadeltg:telegram:bot_id"] != botID || claims["urn:zinusya:purpose"] != "telegram-prelink" || claims["jti"] == "" ||
		claims["sub"] != "telegram:"+botID+":"+opaque || claims["email"] != fmt.Sprintf("tg+%s+%d@telegram.invalid", botID, id) || claims["email_verified"] != true {
		b.lastError.Store("assertion scope mismatch")
		http.Error(w, "scope", 403)
		return
	}
	mode := b.mode.Load().(string)
	switch mode {
	case "denied":
		http.Error(w, "denied", 403)
		return
	case "conflict":
		http.Error(w, "conflict", 409)
		return
	case "outage":
		http.Error(w, "unavailable", 503)
		return
	case "timeout":
		<-r.Context().Done()
		return
	}
	b.mu.Lock()
	b.assertions = append(b.assertions, envelope.Assertion)
	subject, err := b.ensureAccountLocked(r.Context(), id)
	if err == nil {
		err = b.ensureLink(r.Context(), subject, opaque, id)
	}
	b.mu.Unlock()
	if err != nil {
		b.lastError.Store(err.Error())
		http.Error(w, "binding unavailable", 503)
		return
	}
	if !expiry.After(time.Now()) {
		b.lastError.Store("assertion expired after binding")
		http.Error(w, "expired", 403)
		return
	}
	digest := sha256.Sum256([]byte(envelope.Assertion))
	receipt := map[string]any{
		"operation_id": fixtureUUID(envelope.Assertion), "user_id": fixtureUUID("account:" + numeric), "subject": subject, "state": "completed",
		"issuer": origin + "/tg", "assertion_sha256": hex.EncodeToString(digest[:]), "assertion_jti": claims["jti"],
		"bot_id": 123456789, "telegram_user_id": id, "external_subject": opaque, "organization": b.h.organization, "provider_id": b.provider, "expires_at": expiry.Time.UTC(),
	}
	if mode == "wrong-receipt" {
		receipt["provider_id"] = "other-provider"
	}
	if mode == "lose-reply" && b.mode.CompareAndSwap("lose-reply", "normal") {
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(receipt)
}

func (b *prelinkBackend) ensureLink(ctx context.Context, subject, opaque string, id int) error {
	var user map[string]any
	for {
		var err error
		user, err = b.h.callAPI(ctx, "GET", "/management/v1/users/"+subject, nil)
		if err == nil {
			break
		}
		if err = waitForProjection(ctx); err != nil {
			return err
		}
	}
	if nested(user, "user", "details", "resourceOwner") != b.h.organization || nested(user, "user", "human", "email", "email") != fmt.Sprintf("tg+%s+%d@telegram.invalid", botID, id) {
		return errors.New("account authority mismatch")
	}
	expected := "telegram:" + botID + ":" + opaque
	added := false
	for {
		result, err := b.h.callAPI(ctx, "POST", "/v2/users/"+subject+"/links/_search", map[string]any{"query": map[string]any{"limit": 100}})
		if err != nil {
			return err
		}
		if links, ok := result["result"].([]any); ok {
			for _, item := range links {
				link, ok := item.(map[string]any)
				if !ok {
					return errors.New("link format")
				}
				if link["idpId"] == b.provider {
					if link["userId"] == expected {
						return nil
					}
					return errors.New("link conflict")
				}
			}
		}
		if !added {
			_, err = b.h.callAPI(ctx, "POST", "/v2/users/"+subject+"/links", map[string]any{"idpLink": map[string]any{"idpId": b.provider, "userId": expected, "userName": numericName(id)}})
			if err != nil {
				return err
			}
			added = true
		}
		if err = waitForProjection(ctx); err != nil {
			return err
		}
	}
}

// Await read-back without acknowledging a write that is not visible yet.
func waitForProjection(ctx context.Context) error {
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func numericName(id int) string { return fmt.Sprintf("tg+%s+%d@telegram.invalid", botID, id) }

func fixtureUUID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func fixtureSigningKey(ctx context.Context, client *http.Client, endpoint string, token *jwt.Token) (any, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var keys struct{ Keys []struct{ Kid, N, E string } }
	if err = json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}
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
	return nil, errors.New("signing key not found")
}
