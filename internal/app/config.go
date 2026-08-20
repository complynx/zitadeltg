package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a8m/envsubst"
	"go.yaml.in/yaml/v4"
)

const (
	defaultJWTPrivateKeyFile      = "/data/zitadeltg-rsa.pem"
	defaultTelegramIssuer         = "https://oauth.telegram.org"
	defaultTelegramJWKSURL        = "https://oauth.telegram.org/.well-known/jwks.json"
	defaultZitadelUserAgentCookie = "__Host-zitadel.useragent"
)

type Config struct {
	Listen                 string
	LogLevel               slog.Level
	PublicURL              string
	Issuer                 string
	EmailDomain            string
	SyntheticEmailVerified bool
	StateTTL               time.Duration
	Zitadel                ZitadelConfig
	JWT                    JWTConfig
	Telegram               TelegramConfig
	Proxy                  ProxyConfig
	RateLimit              RateLimitConfig
	Bots                   []BotConfig
}

type ZitadelConfig struct {
	JWTEndpoint            string
	JWTHeader              string
	UserAgentCookie        string
	RedirectOrigins        []string
	AllowAnyRedirectOrigin bool
}

type JWTConfig struct {
	TTL            time.Duration
	KeyID          string
	PrivateKeyFile string
	PrivateKeyPEM  string
	Audience       string
}

type TelegramConfig struct {
	Issuer       string
	JWKSURL      string
	JWKSCacheTTL time.Duration
	ClockSkew    time.Duration
}

type ProxyConfig struct {
	TrustedCIDRs  []netip.Prefix
	SecureCookies bool
}

type RateLimitConfig struct {
	Login RateLimitBucketConfig
	Auth  RateLimitBucketConfig
}

type RateLimitBucketConfig struct {
	Requests int
	Window   time.Duration
}

type BotConfig struct {
	ID           string
	Secret       string
	Name         string
	Lang         string
	RequestWrite bool
	RequestPhone bool
}

type rawConfig struct {
	Listen                 string             `yaml:"listen"`
	LogLevel               string             `yaml:"log_level"`
	PublicURL              string             `yaml:"public_url"`
	Issuer                 string             `yaml:"issuer"`
	EmailDomain            string             `yaml:"email_domain"`
	SyntheticEmailVerified bool               `yaml:"synthetic_email_verified"`
	StateTTL               string             `yaml:"state_ttl"`
	Zitadel                rawZitadelConfig   `yaml:"zitadel"`
	JWT                    rawJWTConfig       `yaml:"jwt"`
	Telegram               rawTelegramConfig  `yaml:"telegram"`
	Proxy                  rawProxyConfig     `yaml:"proxy"`
	RateLimit              rawRateLimitConfig `yaml:"rate_limit"`
	Bots                   []rawBotConfig     `yaml:"bots"`
	Aliases                rawTopLevelAliases `yaml:",inline"`
}

type rawTopLevelAliases struct {
	ZitadelJWTEndpoint   string `yaml:"zitadel_jwt_endpoint"`
	ZitadelJWTHeader     string `yaml:"zitadel_jwt_header"`
	JWTTTL               string `yaml:"jwt_ttl"`
	JWTKeyID             string `yaml:"jwt_key_id"`
	JWTPrivateKeyFile    string `yaml:"jwt_private_key_file"`
	JWTPrivateKeyPEM     string `yaml:"jwt_private_key"`
	JWTAudience          string `yaml:"jwt_audience"`
	TelegramIssuer       string `yaml:"telegram_issuer"`
	TelegramJWKSURL      string `yaml:"telegram_jwks_url"`
	TelegramJWKSCacheTTL string `yaml:"telegram_jwks_cache_ttl"`
	TelegramClockSkew    string `yaml:"telegram_clock_skew"`
}

type rawZitadelConfig struct {
	JWTEndpoint            string   `yaml:"jwt_endpoint"`
	JWTHeader              string   `yaml:"jwt_header"`
	UserAgentCookie        string   `yaml:"user_agent_cookie"`
	RedirectOrigins        []string `yaml:"redirect_origins"`
	AllowAnyRedirectOrigin bool     `yaml:"allow_any_redirect_origin"`
}

type rawJWTConfig struct {
	TTL            string `yaml:"ttl"`
	KeyID          string `yaml:"key_id"`
	PrivateKeyFile string `yaml:"private_key_file"`
	PrivateKeyPEM  string `yaml:"private_key"`
	Audience       string `yaml:"audience"`
}

type rawTelegramConfig struct {
	Issuer       string `yaml:"issuer"`
	JWKSURL      string `yaml:"jwks_url"`
	JWKSCacheTTL string `yaml:"jwks_cache_ttl"`
	ClockSkew    string `yaml:"clock_skew"`
}

type rawProxyConfig struct {
	TrustedCIDRs  []string `yaml:"trusted_cidrs"`
	SecureCookies *bool    `yaml:"secure_cookies"`
}

type rawRateLimitConfig struct {
	Login rawRateLimitBucketConfig `yaml:"login"`
	Auth  rawRateLimitBucketConfig `yaml:"auth"`
}

type rawRateLimitBucketConfig struct {
	Requests int    `yaml:"requests"`
	Window   string `yaml:"window"`
}

type rawBotConfig struct {
	Token            string `yaml:"token"`
	Name             string `yaml:"name"`
	Lang             string `yaml:"lang"`
	RequestWrite     bool   `yaml:"write"`
	RequestPhone     bool   `yaml:"phone"`
	RequestWriteLong bool   `yaml:"request_write"`
	RequestPhoneLong bool   `yaml:"request_phone"`
}

type rawConfigPresence struct {
	Zitadel struct {
		JWTEndpoint *string `yaml:"jwt_endpoint"`
		JWTHeader   *string `yaml:"jwt_header"`
	} `yaml:"zitadel"`
	JWT struct {
		TTL            *string `yaml:"ttl"`
		KeyID          *string `yaml:"key_id"`
		PrivateKeyFile *string `yaml:"private_key_file"`
		PrivateKeyPEM  *string `yaml:"private_key"`
		Audience       *string `yaml:"audience"`
	} `yaml:"jwt"`
	Telegram struct {
		Issuer       *string `yaml:"issuer"`
		JWKSURL      *string `yaml:"jwks_url"`
		JWKSCacheTTL *string `yaml:"jwks_cache_ttl"`
		ClockSkew    *string `yaml:"clock_skew"`
	} `yaml:"telegram"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data)
}

func ParseConfig(input []byte) (Config, error) {
	var presence rawConfigPresence
	if err := decodeSingleYAMLDocument(input, &presence, false); err != nil {
		return Config{}, err
	}
	raw := rawConfig{
		Listen:      ":8080",
		LogLevel:    "info",
		EmailDomain: "telegram.invalid",
		StateTTL:    "10m",
		Zitadel: rawZitadelConfig{
			JWTHeader:       "x-zitadel-jwt",
			UserAgentCookie: defaultZitadelUserAgentCookie,
		},
		JWT: rawJWTConfig{
			TTL:   "2m",
			KeyID: "zitadeltg-1",
		},
		Telegram: rawTelegramConfig{
			Issuer:       defaultTelegramIssuer,
			JWKSURL:      defaultTelegramJWKSURL,
			JWKSCacheTTL: "1h",
			ClockSkew:    "30s",
		},
		Proxy: rawProxyConfig{
			TrustedCIDRs:  []string{"127.0.0.1/32", "::1/128"},
			SecureCookies: boolPtr(true),
		},
		RateLimit: rawRateLimitConfig{
			Login: rawRateLimitBucketConfig{Requests: 60, Window: "1m"},
			Auth:  rawRateLimitBucketConfig{Requests: 20, Window: "1m"},
		},
	}
	if err := decodeSingleYAMLDocument(input, &raw, true); err != nil {
		return Config{}, err
	}
	if err := raw.expandEnv(); err != nil {
		return Config{}, err
	}
	if err := raw.applyAliases(presence); err != nil {
		return Config{}, err
	}
	return finalizeConfig(raw)
}

func decodeSingleYAMLDocument(input []byte, target any, knownFields bool) error {
	decoder := yaml.NewDecoder(bytes.NewReader(input))
	decoder.KnownFields(knownFields)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	err := decoder.Decode(&trailing)
	if err == nil {
		return errors.New("multiple YAML documents are not supported")
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (raw *rawConfig) expandEnv() error {
	fields := []*string{
		&raw.Listen,
		&raw.LogLevel,
		&raw.PublicURL,
		&raw.Issuer,
		&raw.EmailDomain,
		&raw.StateTTL,
		&raw.Zitadel.JWTEndpoint,
		&raw.Zitadel.JWTHeader,
		&raw.Zitadel.UserAgentCookie,
		&raw.JWT.TTL,
		&raw.JWT.KeyID,
		&raw.JWT.PrivateKeyFile,
		&raw.JWT.PrivateKeyPEM,
		&raw.JWT.Audience,
		&raw.Telegram.Issuer,
		&raw.Telegram.JWKSURL,
		&raw.Telegram.JWKSCacheTTL,
		&raw.Telegram.ClockSkew,
		&raw.RateLimit.Login.Window,
		&raw.RateLimit.Auth.Window,
		&raw.Aliases.ZitadelJWTEndpoint,
		&raw.Aliases.ZitadelJWTHeader,
		&raw.Aliases.JWTTTL,
		&raw.Aliases.JWTKeyID,
		&raw.Aliases.JWTPrivateKeyFile,
		&raw.Aliases.JWTPrivateKeyPEM,
		&raw.Aliases.JWTAudience,
		&raw.Aliases.TelegramIssuer,
		&raw.Aliases.TelegramJWKSURL,
		&raw.Aliases.TelegramJWKSCacheTTL,
		&raw.Aliases.TelegramClockSkew,
	}
	for i := range raw.Bots {
		fields = append(fields, &raw.Bots[i].Token, &raw.Bots[i].Name, &raw.Bots[i].Lang)
	}
	for i := range raw.Proxy.TrustedCIDRs {
		fields = append(fields, &raw.Proxy.TrustedCIDRs[i])
	}
	for i := range raw.Zitadel.RedirectOrigins {
		fields = append(fields, &raw.Zitadel.RedirectOrigins[i])
	}
	for _, field := range fields {
		value, err := expandConfigString(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func expandConfigString(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return envsubst.StringRestricted(value, true, false)
}

func (raw *rawConfig) applyAliases(presence rawConfigPresence) error {
	if raw.Aliases.ZitadelJWTEndpoint != "" {
		if presence.Zitadel.JWTEndpoint != nil {
			return errors.New("cannot specify both zitadel.jwt_endpoint and zitadel_jwt_endpoint")
		}
		raw.Zitadel.JWTEndpoint = raw.Aliases.ZitadelJWTEndpoint
	}
	if raw.Aliases.ZitadelJWTHeader != "" {
		if presence.Zitadel.JWTHeader != nil {
			return errors.New("cannot specify both zitadel.jwt_header and zitadel_jwt_header")
		}
		raw.Zitadel.JWTHeader = raw.Aliases.ZitadelJWTHeader
	}
	if raw.Aliases.JWTTTL != "" {
		if presence.JWT.TTL != nil {
			return errors.New("cannot specify both jwt.ttl and jwt_ttl")
		}
		raw.JWT.TTL = raw.Aliases.JWTTTL
	}
	if raw.Aliases.JWTKeyID != "" {
		if presence.JWT.KeyID != nil {
			return errors.New("cannot specify both jwt.key_id and jwt_key_id")
		}
		raw.JWT.KeyID = raw.Aliases.JWTKeyID
	}
	if raw.Aliases.JWTPrivateKeyFile != "" {
		if presence.JWT.PrivateKeyFile != nil {
			return errors.New("cannot specify both jwt.private_key_file and jwt_private_key_file")
		}
		raw.JWT.PrivateKeyFile = raw.Aliases.JWTPrivateKeyFile
	}
	if raw.Aliases.JWTPrivateKeyPEM != "" {
		if presence.JWT.PrivateKeyPEM != nil {
			return errors.New("cannot specify both jwt.private_key and jwt_private_key")
		}
		raw.JWT.PrivateKeyPEM = raw.Aliases.JWTPrivateKeyPEM
	}
	if raw.Aliases.JWTAudience != "" {
		if presence.JWT.Audience != nil {
			return errors.New("cannot specify both jwt.audience and jwt_audience")
		}
		raw.JWT.Audience = raw.Aliases.JWTAudience
	}
	if raw.Aliases.TelegramIssuer != "" {
		if presence.Telegram.Issuer != nil {
			return errors.New("cannot specify both telegram.issuer and telegram_issuer")
		}
		raw.Telegram.Issuer = raw.Aliases.TelegramIssuer
	}
	if raw.Aliases.TelegramJWKSURL != "" {
		if presence.Telegram.JWKSURL != nil {
			return errors.New("cannot specify both telegram.jwks_url and telegram_jwks_url")
		}
		raw.Telegram.JWKSURL = raw.Aliases.TelegramJWKSURL
	}
	if raw.Aliases.TelegramJWKSCacheTTL != "" {
		if presence.Telegram.JWKSCacheTTL != nil {
			return errors.New("cannot specify both telegram.jwks_cache_ttl and telegram_jwks_cache_ttl")
		}
		raw.Telegram.JWKSCacheTTL = raw.Aliases.TelegramJWKSCacheTTL
	}
	if raw.Aliases.TelegramClockSkew != "" {
		if presence.Telegram.ClockSkew != nil {
			return errors.New("cannot specify both telegram.clock_skew and telegram_clock_skew")
		}
		raw.Telegram.ClockSkew = raw.Aliases.TelegramClockSkew
	}
	return nil
}

func finalizeConfig(raw rawConfig) (Config, error) {
	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(strings.TrimSpace(raw.LogLevel))); err != nil {
		return Config{}, fmt.Errorf("log_level: %w", err)
	}
	jwtTTL, err := time.ParseDuration(raw.JWT.TTL)
	if err != nil {
		return Config{}, fmt.Errorf("jwt.ttl: %w", err)
	}
	stateTTL, err := time.ParseDuration(raw.StateTTL)
	if err != nil {
		return Config{}, fmt.Errorf("state_ttl: %w", err)
	}
	jwksTTL, err := time.ParseDuration(raw.Telegram.JWKSCacheTTL)
	if err != nil {
		return Config{}, fmt.Errorf("telegram.jwks_cache_ttl: %w", err)
	}
	clockSkew, err := time.ParseDuration(raw.Telegram.ClockSkew)
	if err != nil {
		return Config{}, fmt.Errorf("telegram.clock_skew: %w", err)
	}
	proxyCIDRs, err := parseCIDRList("proxy.trusted_cidrs", raw.Proxy.TrustedCIDRs)
	if err != nil {
		return Config{}, err
	}
	loginLimit, err := parseRateLimitBucket("rate_limit.login", raw.RateLimit.Login)
	if err != nil {
		return Config{}, err
	}
	authLimit, err := parseRateLimitBucket("rate_limit.auth", raw.RateLimit.Auth)
	if err != nil {
		return Config{}, err
	}
	secureCookies := true
	if raw.Proxy.SecureCookies != nil {
		secureCookies = *raw.Proxy.SecureCookies
	}
	privateKeyFile := strings.TrimSpace(raw.JWT.PrivateKeyFile)
	privateKeyPEM := strings.ReplaceAll(strings.TrimSpace(raw.JWT.PrivateKeyPEM), `\n`, "\n")
	if privateKeyFile != "" && privateKeyPEM != "" {
		return Config{}, errors.New("configure only one of jwt.private_key_file or jwt.private_key")
	}
	if privateKeyFile == "" && privateKeyPEM == "" {
		privateKeyFile = defaultJWTPrivateKeyFile
	}
	redirectOrigins, err := normalizeRedirectOrigins(raw.Zitadel.RedirectOrigins)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Listen:                 strings.TrimSpace(raw.Listen),
		LogLevel:               logLevel,
		PublicURL:              strings.TrimSpace(raw.PublicURL),
		Issuer:                 strings.TrimSpace(raw.Issuer),
		EmailDomain:            strings.TrimSpace(raw.EmailDomain),
		SyntheticEmailVerified: raw.SyntheticEmailVerified,
		StateTTL:               stateTTL,
		Zitadel: ZitadelConfig{
			JWTEndpoint:            strings.TrimSpace(raw.Zitadel.JWTEndpoint),
			JWTHeader:              strings.TrimSpace(raw.Zitadel.JWTHeader),
			UserAgentCookie:        strings.TrimSpace(raw.Zitadel.UserAgentCookie),
			RedirectOrigins:        redirectOrigins,
			AllowAnyRedirectOrigin: raw.Zitadel.AllowAnyRedirectOrigin,
		},
		JWT: JWTConfig{
			TTL:            jwtTTL,
			KeyID:          strings.TrimSpace(raw.JWT.KeyID),
			PrivateKeyFile: privateKeyFile,
			PrivateKeyPEM:  privateKeyPEM,
			Audience:       strings.TrimSpace(raw.JWT.Audience),
		},
		Telegram: TelegramConfig{
			Issuer:       strings.TrimSpace(raw.Telegram.Issuer),
			JWKSURL:      strings.TrimSpace(raw.Telegram.JWKSURL),
			JWKSCacheTTL: jwksTTL,
			ClockSkew:    clockSkew,
		},
		Proxy: ProxyConfig{
			TrustedCIDRs:  proxyCIDRs,
			SecureCookies: secureCookies,
		},
		RateLimit: RateLimitConfig{
			Login: loginLimit,
			Auth:  authLimit,
		},
	}
	if cfg.Issuer == "" {
		cfg.Issuer = cfg.PublicURL
	}
	if cfg.Issuer == "" {
		return Config{}, errors.New("issuer or public_url is required")
	}
	if cfg.Listen == "" {
		return Config{}, errors.New("listen must not be empty")
	}
	if cfg.EmailDomain == "" {
		return Config{}, errors.New("email_domain is required")
	}
	if cfg.SyntheticEmailVerified && !isReservedInvalidDomain(cfg.EmailDomain) {
		return Config{}, errors.New("synthetic_email_verified requires email_domain to be a subdomain of the reserved invalid domain")
	}
	if cfg.Zitadel.JWTEndpoint == "" {
		return Config{}, errors.New("zitadel.jwt_endpoint is required")
	}
	if cfg.Zitadel.JWTHeader == "" {
		return Config{}, errors.New("zitadel.jwt_header is required")
	}
	if cfg.Zitadel.UserAgentCookie == "" {
		return Config{}, errors.New("zitadel.user_agent_cookie is required")
	}
	if cfg.JWT.KeyID == "" {
		return Config{}, errors.New("jwt.key_id is required")
	}
	if cfg.JWT.Audience == "" {
		cfg.JWT.Audience = cfg.Zitadel.JWTEndpoint
	}
	if cfg.JWT.TTL < minimumConfiguredJWTTTL {
		return Config{}, fmt.Errorf("jwt.ttl must be at least %s", minimumConfiguredJWTTTL)
	}
	if cfg.JWT.TTL > 15*time.Minute {
		return Config{}, errors.New("jwt.ttl must be 15m or less")
	}
	if cfg.StateTTL < time.Second {
		return Config{}, errors.New("state_ttl must be at least 1s")
	}
	if cfg.StateTTL > 30*time.Minute {
		return Config{}, errors.New("state_ttl must be 30m or less")
	}
	if cfg.Telegram.Issuer == "" {
		return Config{}, errors.New("telegram.issuer is required")
	}
	if cfg.Telegram.JWKSURL == "" {
		return Config{}, errors.New("telegram.jwks_url is required")
	}
	if cfg.Telegram.JWKSCacheTTL <= 0 {
		return Config{}, errors.New("telegram.jwks_cache_ttl must be positive")
	}
	if cfg.Telegram.ClockSkew < 0 || cfg.Telegram.ClockSkew > 5*time.Minute {
		return Config{}, errors.New("telegram.clock_skew must be between 0 and 5m")
	}
	if err := validateHTTPSURL("issuer", cfg.Issuer); err != nil {
		return Config{}, err
	}
	if err := rejectURLQueryOrFragment("issuer", cfg.Issuer); err != nil {
		return Config{}, err
	}
	if cfg.PublicURL != "" {
		if err := validateHTTPSURL("public_url", cfg.PublicURL); err != nil {
			return Config{}, err
		}
		if err := rejectURLQueryOrFragment("public_url", cfg.PublicURL); err != nil {
			return Config{}, err
		}
	}
	if err := validateHTTPSURL("zitadel.jwt_endpoint", cfg.Zitadel.JWTEndpoint); err != nil {
		return Config{}, err
	}
	zitadelEndpoint, _ := url.Parse(cfg.Zitadel.JWTEndpoint)
	if zitadelEndpoint.RawQuery != "" || zitadelEndpoint.Fragment != "" {
		return Config{}, errors.New("zitadel.jwt_endpoint must not include a query or fragment")
	}
	if err := validateHTTPSURL("telegram.issuer", cfg.Telegram.Issuer); err != nil {
		return Config{}, err
	}
	if err := rejectURLQueryOrFragment("telegram.issuer", cfg.Telegram.Issuer); err != nil {
		return Config{}, err
	}
	if err := validateHTTPSURL("telegram.jwks_url", cfg.Telegram.JWKSURL); err != nil {
		return Config{}, err
	}
	if !validJWTHeaderName(cfg.Zitadel.JWTHeader) {
		return Config{}, fmt.Errorf("zitadel.jwt_header %q is not a safe HTTP header name", cfg.Zitadel.JWTHeader)
	}
	if !validHTTPHeaderName(cfg.Zitadel.UserAgentCookie) {
		return Config{}, fmt.Errorf("zitadel.user_agent_cookie %q is not a safe cookie name", cfg.Zitadel.UserAgentCookie)
	}
	switch cfg.Zitadel.UserAgentCookie {
	case secureSessionCookieName, insecureSessionCookieName:
		return Config{}, errors.New("zitadel.user_agent_cookie must not reuse a zitadeltg session cookie name")
	}
	if !validEmailDomain(cfg.EmailDomain) {
		return Config{}, fmt.Errorf("email_domain %q is not valid", cfg.EmailDomain)
	}
	if len(raw.Bots) == 0 {
		return Config{}, errors.New("at least one bot is required")
	}

	seen := map[string]struct{}{}
	for i, rawBot := range raw.Bots {
		id, secret, err := parseBotToken(rawBot.Token)
		if err != nil {
			return Config{}, fmt.Errorf("bots[%d].token: %w", i, err)
		}
		if _, ok := seen[id]; ok {
			return Config{}, fmt.Errorf("bots[%d].token: duplicate bot id %s", i, id)
		}
		seen[id] = struct{}{}

		name := strings.TrimPrefix(strings.TrimSpace(rawBot.Name), "@")
		if name == "" {
			name = "bot-" + id
		}
		cfg.Bots = append(cfg.Bots, BotConfig{
			ID:           id,
			Secret:       secret,
			Name:         name,
			Lang:         strings.TrimSpace(rawBot.Lang),
			RequestWrite: rawBot.RequestWrite || rawBot.RequestWriteLong,
			RequestPhone: rawBot.RequestPhone || rawBot.RequestPhoneLong,
		})
	}
	return cfg, nil
}

func validateHTTPSURL(name string, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute https URL", name)
	}
	if parsed.User != nil {
		return fmt.Errorf("%s must not include userinfo", name)
	}
	return nil
}

func rejectURLQueryOrFragment(name string, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must not include a query or fragment", name)
	}
	return nil
}

func normalizeRedirectOrigins(values []string) ([]string, error) {
	origins := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("zitadel.redirect_origins[%d]: %w", i, err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("zitadel.redirect_origins[%d] must be an HTTPS origin without path, userinfo, query, or fragment", i)
		}
		origin := canonicalHTTPSOrigin(parsed)
		if _, exists := seen[origin]; exists {
			return nil, fmt.Errorf("zitadel.redirect_origins[%d] duplicates %q", i, origin)
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins, nil
}

func canonicalHTTPSOrigin(parsed *url.URL) string {
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" && port != "443" {
		host += ":" + port
	}
	return "https://" + host
}

func isReservedInvalidDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.HasSuffix(domain, ".invalid")
}

const maxSyntheticEmailDomainBytes = 254 - 1 - 64

func validEmailDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" || len(domain) > maxSyntheticEmailDomainBytes || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r > 127 || !isHTTPTokenChar(byte(r)) {
			return false
		}
	}
	return true
}

func validJWTHeaderName(name string) bool {
	if !validHTTPHeaderName(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "accept", "host", "content-length", "connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
		"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port",
		"x-forwarded-proto", "cookie", "origin", "referer":
		return false
	default:
		return true
	}
}

func isHTTPTokenChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func parseBotToken(token string) (string, string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", errors.New("empty token")
	}
	id, secret, ok := strings.Cut(token, ":")
	if !ok {
		return "", "", errors.New("must be BOT_ID:BOT_SECRET")
	}
	if id == "" || secret == "" {
		return "", "", errors.New("bot id and secret must be non-empty")
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return "", "", fmt.Errorf("bot id %q must be numeric", id)
		}
	}
	numericID, err := strconv.ParseUint(id, 10, 52)
	if err != nil || numericID > uint64(maxTelegramNumericID) {
		return "", "", fmt.Errorf("bot id %q exceeds Telegram's 52-bit numeric ID range", id)
	}
	if numericID == 0 {
		return "", "", errors.New("bot id must be positive")
	}
	if strconv.FormatUint(numericID, 10) != id {
		return "", "", errors.New("bot id must use canonical decimal form without leading zeros")
	}
	return id, secret, nil
}

func parseCIDRList(name string, values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			addr, addrErr := netip.ParseAddr(value)
			if addrErr != nil {
				return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func parseRateLimitBucket(name string, raw rawRateLimitBucketConfig) (RateLimitBucketConfig, error) {
	if raw.Requests < 0 {
		return RateLimitBucketConfig{}, fmt.Errorf("%s.requests must be non-negative", name)
	}
	if raw.Requests == 0 {
		return RateLimitBucketConfig{}, nil
	}
	window, err := time.ParseDuration(raw.Window)
	if err != nil {
		return RateLimitBucketConfig{}, fmt.Errorf("%s.window: %w", name, err)
	}
	if window <= 0 {
		return RateLimitBucketConfig{}, fmt.Errorf("%s.window must be positive", name)
	}
	if window > time.Hour {
		return RateLimitBucketConfig{}, fmt.Errorf("%s.window must be 1h or less", name)
	}
	return RateLimitBucketConfig{
		Requests: raw.Requests,
		Window:   window,
	}, nil
}

func boolPtr(value bool) *bool {
	return &value
}
