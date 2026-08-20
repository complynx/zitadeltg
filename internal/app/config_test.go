package app

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigExpandsEnvAndBots(t *testing.T) {
	input := `
listen: ":9000"
issuer: "https://idp.example.com/root"
email_domain: "login.invalid"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
  jwt_header: "x-test-jwt"
jwt:
  ttl: "90s"
  key_id: "test-key"
telegram:
  jwks_url: "https://oauth.telegram.org/.well-known/jwks.json"
bots:
  - token: "${BOT_MAIN}"
    name: "Main_Bot"
    write: true
    phone: false
`
	t.Setenv("BOT_MAIN", "123456789:secret")
	cfg, err := ParseConfig([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, ":9000", cfg.Listen)
	assert.Equal(t, "x-test-jwt", cfg.Zitadel.JWTHeader)
	assert.Equal(t, defaultZitadelUserAgentCookie, cfg.Zitadel.UserAgentCookie)
	assert.Equal(t, defaultJWTPrivateKeyFile, cfg.JWT.PrivateKeyFile)
	require.Len(t, cfg.Bots, 1)
	bot := cfg.Bots[0]
	assert.Equal(t, "123456789", bot.ID)
	assert.Equal(t, "secret", bot.Secret)
	assert.Equal(t, "Main_Bot", bot.Name)
	assert.True(t, bot.RequestWrite)
	assert.False(t, bot.RequestPhone)
	assert.False(t, cfg.SyntheticEmailVerified)
	assert.Equal(t, slog.LevelInfo, cfg.LogLevel)
}

func TestParseConfigAcceptsCustomZitadelUserAgentCookie(t *testing.T) {
	t.Setenv("ZITADEL_UA_COOKIE", "zitadel.custom-useragent")
	cfg, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
  user_agent_cookie: "${ZITADEL_UA_COOKIE}"
bots:
  - token: "123456789:secret"
`))
	require.NoError(t, err)
	assert.Equal(t, "zitadel.custom-useragent", cfg.Zitadel.UserAgentCookie)
}

func TestParseConfigRejectsUnsafeZitadelUserAgentCookie(t *testing.T) {
	_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
  user_agent_cookie: "bad cookie"
bots:
  - token: "123456789:secret"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "safe cookie name")
}

func TestParseConfigRejectsZitadeltgSessionAsUserAgentCookie(t *testing.T) {
	for _, cookieName := range []string{secureSessionCookieName, insecureSessionCookieName} {
		t.Run(cookieName, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
  user_agent_cookie: "` + cookieName + `"
bots:
  - token: "123456789:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not reuse")
		})
	}
}

func TestParseConfigAcceptsDebugLogLevel(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
log_level: debug
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`))
	require.NoError(t, err)
	assert.Equal(t, slog.LevelDebug, cfg.LogLevel)
}

func TestParseConfigRejectsInvalidLogLevel(t *testing.T) {
	_, err := ParseConfig([]byte(`
log_level: verbose
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "log_level")
}

func TestParseConfigPreservesExactIssuerIdentifiers(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
issuer: "https://idp.example.com/tenant/"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
telegram:
  issuer: "https://telegram.example.com/oidc/"
bots:
  - token: "123456789:secret"
`))
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/tenant/", cfg.Issuer)
	assert.Equal(t, "https://telegram.example.com/oidc/", cfg.Telegram.Issuer)
}

func TestParseConfigAllowsVerifiedSyntheticEmailOnlyForInvalidSubdomains(t *testing.T) {
	base := func(domain, enabled string) string {
		return `
issuer: "https://idp.example.com"
email_domain: "` + domain + `"
synthetic_email_verified: ` + enabled + `
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`
	}

	tests := []struct {
		name    string
		domain  string
		enabled string
		wantOK  bool
	}{
		{name: "reserved subdomain", domain: "login.invalid", enabled: "true", wantOK: true},
		{name: "case insensitive", domain: "LOGIN.INVALID", enabled: "true", wantOK: true},
		{name: "bare reserved label is not an email domain", domain: "invalid", enabled: "true"},
		{name: "public domain", domain: "example.com", enabled: "true"},
		{name: "suffix without label boundary", domain: "foo.evilinvalid", enabled: "true"},
		{name: "empty leading label", domain: ".invalid", enabled: "true"},
		{name: "empty middle label", domain: "foo..invalid", enabled: "true"},
		{name: "overlong label", domain: strings.Repeat("a", 64) + ".invalid", enabled: "true"},
		{name: "disabled remains backward compatible", domain: "example.com", enabled: "false", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig([]byte(base(tt.domain, tt.enabled)))
			if tt.wantOK {
				require.NoError(t, err)
				assert.Equal(t, tt.enabled == "true", cfg.SyntheticEmailVerified)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestParseConfigRejectsEmptyListen(t *testing.T) {
	_, err := ParseConfig([]byte(`
listen: ""
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen")
}

func TestParseConfigProxyAndRateLimit(t *testing.T) {
	input := `
issuer: "https://idp.example.com"
email_domain: "login.invalid"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
proxy:
  trusted_cidrs:
    - "${TRAEFIK_CIDR}"
  secure_cookies: false
rate_limit:
  login:
    requests: 0
  auth:
    requests: 3
    window: "30s"
bots:
  - token: "${BOT_MAIN}"
`
	t.Setenv("BOT_MAIN", "123456789:secret")
	t.Setenv("TRAEFIK_CIDR", "172.18.0.0/16")

	cfg, err := ParseConfig([]byte(input))
	require.NoError(t, err)
	require.Len(t, cfg.Proxy.TrustedCIDRs, 1)
	assert.Equal(t, netip.MustParsePrefix("172.18.0.0/16"), cfg.Proxy.TrustedCIDRs[0])
	assert.False(t, cfg.Proxy.SecureCookies)
	assert.Zero(t, cfg.RateLimit.Login.Requests)
	assert.Equal(t, 3, cfg.RateLimit.Auth.Requests)
	assert.Equal(t, 30*time.Second, cfg.RateLimit.Auth.Window)
}

func TestParseConfigRequiresEnvPlaceholder(t *testing.T) {
	_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "${MISSING_BOT_TOKEN}"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MISSING_BOT_TOKEN")
}

func TestParseConfigLegacyAliasesOverrideDefaults(t *testing.T) {
	t.Setenv("BOT_MAIN", "123456789:secret")
	cfg, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel_jwt_endpoint: "https://accounts.example.com/idps/jwt"
zitadel_jwt_header: "x-legacy-jwt"
jwt_ttl: "3m"
jwt_key_id: "legacy-key"
telegram_jwks_url: "https://telegram.example.com/keys"
bots:
  - token: "${BOT_MAIN}"
`))
	require.NoError(t, err)
	assert.Equal(t, "x-legacy-jwt", cfg.Zitadel.JWTHeader)
	assert.Equal(t, 3*time.Minute, cfg.JWT.TTL)
	assert.Equal(t, "legacy-key", cfg.JWT.KeyID)
	assert.Equal(t, "https://telegram.example.com/keys", cfg.Telegram.JWKSURL)
}

func TestParseConfigRejectsLegacyAndNestedConflict(t *testing.T) {
	_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
jwt:
  ttl: "2m"
jwt_ttl: "3m"
bots:
  - token: "123456789:secret"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot specify both jwt.ttl and jwt_ttl")
}

func TestParseConfigRejectsReservedJWTHeaders(t *testing.T) {
	for _, header := range []string{
		"Accept", "Host", "Content-Length", "Connection", "Transfer-Encoding", "Trailer",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"Cookie", "Origin", "Referer",
	} {
		t.Run(header, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
  jwt_header: "` + header + `"
bots:
  - token: "123456789:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "safe HTTP header")
		})
	}
}

func TestParseConfigRejectsMultiplePrivateKeySources(t *testing.T) {
	_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
jwt:
  private_key_file: "/data/key.pem"
  private_key: "not-used"
bots:
  - token: "123456789:secret"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one")
}

func TestParseConfigRejectsBotIDOutsideTelegramRange(t *testing.T) {
	for _, id := range []string{"4503599627370496", "9007199254740992"} {
		t.Run(id, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "` + id + `:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "52-bit numeric ID range")
		})
	}
}

func TestParseConfigRejectsNonCanonicalBotIDs(t *testing.T) {
	for _, id := range []string{"0", "00123"} {
		t.Run(id, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "` + id + `:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "bot id")
		})
	}
}

func TestParseConfigRejectsURLQueriesAndFragments(t *testing.T) {
	tests := map[string]string{
		"issuer query":             `issuer: "https://idp.example.com?secret=value"`,
		"issuer fragment":          `issuer: "https://idp.example.com#fragment"`,
		"public URL query":         "issuer: \"https://idp.example.com\"\npublic_url: \"https://public.example.com?secret=value\"",
		"Telegram issuer fragment": "issuer: \"https://idp.example.com\"\ntelegram:\n  issuer: \"https://oauth.telegram.org#fragment\"",
	}
	for name, fields := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(fields + `
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not include a query or fragment")
		})
	}
}

func TestParseConfigRejectsSubsecondTokenTTLs(t *testing.T) {
	for name, test := range map[string]struct {
		field string
		want  string
	}{
		"JWT":   {field: "jwt:\n  ttl: \"500ms\"", want: "at least 6s"},
		"state": {field: "state_ttl: \"500ms\"", want: "at least 1s"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
` + test.field + `
bots:
  - token: "123456789:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.want)
		})
	}
}

func TestValidEmailDomainReservesFullLocalPart(t *testing.T) {
	maximum := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61)
	require.Len(t, maximum, maxSyntheticEmailDomainBytes)
	assert.True(t, validEmailDomain(maximum))
	assert.False(t, validEmailDomain(maximum+"d"))
}

func TestParseConfigValidatesRedirectOrigins(t *testing.T) {
	for _, origin := range []string{
		"http://app.example.com",
		"https://user@app.example.com",
		"https://app.example.com/path",
		"https://app.example.com?secret=value",
	} {
		t.Run(origin, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
  redirect_origins:
    - "` + origin + `"
bots:
  - token: "123456789:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "redirect_origins")
		})
	}
}

func TestParseConfigAcceptsMinimumJWTTTL(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
jwt:
  ttl: "6s"
bots:
  - token: "123456789:secret"
`))
	require.NoError(t, err)
	assert.Equal(t, minimumConfiguredJWTTTL, cfg.JWT.TTL)
}

func TestParseConfigRejectsMalformedEmailDomains(t *testing.T) {
	for _, domain := range []string{".example.com", "example..com", "-bad.example", "bad-.example", "example.com?x"} {
		t.Run(domain, func(t *testing.T) {
			_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
email_domain: "` + domain + `"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "email_domain")
		})
	}
}

func TestParseConfigRejectsZitadelEndpointQuery(t *testing.T) {
	_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt?requestID=fixed"
bots:
  - token: "123456789:secret"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not include a query")
}

func TestParseConfigDefaultsAudienceToZitadelEndpoint(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
`))
	require.NoError(t, err)
	assert.Equal(t, cfg.Zitadel.JWTEndpoint, cfg.JWT.Audience)
}

func TestParseConfigRejectsMultipleYAMLDocuments(t *testing.T) {
	_, err := ParseConfig([]byte(`
issuer: "https://idp.example.com"
zitadel:
  jwt_endpoint: "https://accounts.example.com/idps/jwt"
bots:
  - token: "123456789:secret"
---
issuer: "https://other.example.com"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple YAML documents")
}
