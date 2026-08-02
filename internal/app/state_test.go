package app

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateRoundTrip(t *testing.T) {
	bot := BotConfig{ID: "123", Secret: "secret"}
	now := time.Unix(1700000000, 0)
	state, err := signState(bot, "requestID=abc&foo=bar", "nonce", now)
	require.NoError(t, err)
	decoded, err := verifyState(bot, state, now.Add(time.Minute), 10*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "requestID=abc&foo=bar", decoded.Query)
	assert.Equal(t, "nonce", decoded.Nonce)
}

func TestStateRejectsTampering(t *testing.T) {
	bot := BotConfig{ID: "123", Secret: "secret"}
	state, err := signState(bot, "requestID=abc", "nonce", time.Now())
	require.NoError(t, err)
	tampered := []byte(state)
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	_, err = verifyState(bot, string(tampered), time.Now(), 10*time.Minute)
	require.Error(t, err)
}

func TestStateRejectsExpired(t *testing.T) {
	bot := BotConfig{ID: "123", Secret: "secret"}
	now := time.Unix(1700000000, 0)
	state, err := signState(bot, "requestID=abc", "nonce", now)
	require.NoError(t, err)
	_, err = verifyState(bot, state, now.Add(11*time.Minute), 10*time.Minute)
	require.Error(t, err)
}

func TestStateRejectsExactExpiryBoundary(t *testing.T) {
	bot := BotConfig{ID: "123", Secret: "secret"}
	now := time.Unix(1700000000, 0)
	state, err := signState(bot, "requestID=abc", "nonce", now)
	require.NoError(t, err)
	_, err = verifyState(bot, state, now.Add(10*time.Minute), 10*time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestStatePreservesSubsecondLifetime(t *testing.T) {
	bot := BotConfig{ID: "123", Secret: "secret"}
	issued := time.Unix(1700000000, 999*int64(time.Millisecond))
	state, err := signState(bot, "requestID=abc", "nonce", issued)
	require.NoError(t, err)
	_, err = verifyState(bot, state, issued.Add(999*time.Millisecond), time.Second)
	require.NoError(t, err)
	_, err = verifyState(bot, state, issued.Add(time.Second), time.Second)
	require.Error(t, err)
}

func TestStateRejectsDifferentBotWithSharedSecret(t *testing.T) {
	first := BotConfig{ID: "123", Secret: "shared-secret"}
	second := BotConfig{ID: "456", Secret: "shared-secret"}
	state, err := signState(first, "requestID=abc", "nonce", time.Now())
	require.NoError(t, err)
	_, err = verifyState(second, state, time.Now(), 10*time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state bot")
}
