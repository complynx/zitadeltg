package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type loginState struct {
	BotID string `json:"bot_id"`
	Query string `json:"query"`
	Nonce string `json:"nonce"`
	IatMS int64  `json:"iat_ms"`
}

func newNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func signState(bot BotConfig, query string, nonce string, now time.Time) (string, error) {
	state := loginState{
		BotID: bot.ID,
		Query: query,
		Nonce: nonce,
		IatMS: now.UnixMilli(),
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signature := stateMAC(bot.Secret, payloadPart)
	return payloadPart + "." + signature, nil
}

func verifyState(bot BotConfig, encoded string, now time.Time, ttl time.Duration) (loginState, error) {
	payloadPart, signature, ok := cutToken(encoded)
	if !ok {
		return loginState{}, errors.New("invalid state format")
	}
	expected := stateMAC(bot.Secret, payloadPart)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return loginState{}, errors.New("invalid state signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return loginState{}, fmt.Errorf("decode state: %w", err)
	}
	var state loginState
	if err := json.Unmarshal(payload, &state); err != nil {
		return loginState{}, fmt.Errorf("parse state: %w", err)
	}
	issued := time.UnixMilli(state.IatMS)
	if !now.Before(issued.Add(ttl)) {
		return loginState{}, errors.New("state expired")
	}
	if issued.After(now.Add(1 * time.Minute)) {
		return loginState{}, errors.New("state issued in the future")
	}
	if state.Nonce == "" {
		return loginState{}, errors.New("state nonce is empty")
	}
	if state.BotID != bot.ID {
		return loginState{}, errors.New("state bot does not match")
	}
	return state, nil
}

func stateMAC(secret string, payloadPart string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadPart))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func cutToken(token string) (string, string, bool) {
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			return token[:i], token[i+1:], token[:i] != "" && token[i+1:] != ""
		}
	}
	return "", "", false
}
