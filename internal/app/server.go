package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxAuthFormBytes          = 64 * 1024
	maxLoginQueryBytes        = 2048
	minimumRelayLifetime      = 5 * time.Second
	minimumConfiguredJWTTTL   = minimumRelayLifetime + time.Second
	secureSessionCookieName   = "__Host-zitadeltg_session"
	insecureSessionCookieName = "zitadeltg_session"
)

type Server struct {
	cfg           Config
	signer        *Signer
	telegram      *TelegramValidator
	proxyClient   *http.Client
	loginPage     *template.Template
	botsByID      map[string]BotConfig
	loginLimits   *requestLimiter
	authLimits    *requestLimiter
	rateLimitLogs *requestLimiter
	pendingStates *pendingStateStore
	logger        *slog.Logger
}

func NewServer(ctx context.Context, cfg Config, signer *Signer, httpClient *http.Client, loggers ...*slog.Logger) (*Server, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if signer == nil {
		return nil, errors.New("JWT signer is required")
	}
	if cfg.JWT.Audience == "" {
		return nil, errors.New("JWT audience is required")
	}
	httpClient = withDefaultHTTPTimeout(httpClient)
	logger := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	}
	loginPage, err := template.New("login").Funcs(template.FuncMap{"json": templateJSON}).Parse(loginHTML)
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}
	proxyClient := &http.Client{
		Transport: httpClient.Transport,
		Timeout:   httpClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	telegram, err := NewTelegramValidator(ctx, cfg.Telegram, httpClient, logger)
	if err != nil {
		return nil, err
	}
	bots := make(map[string]BotConfig, len(cfg.Bots))
	for _, bot := range cfg.Bots {
		bots[bot.ID] = bot
	}
	return &Server{
		cfg:           cfg,
		signer:        signer,
		telegram:      telegram,
		proxyClient:   proxyClient,
		loginPage:     loginPage,
		botsByID:      bots,
		loginLimits:   newRequestLimiter(cfg.RateLimit.Login),
		authLimits:    newRequestLimiter(cfg.RateLimit.Auth),
		rateLimitLogs: newRequestLimiter(RateLimitBucketConfig{Requests: 5, Window: time.Minute}),
		pendingStates: newPendingStateStore(),
		logger:        logger,
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setCommonSecurityHeaders(w.Header())
	if pathHasSuffix(r.URL.Path, "/healthz") {
		s.handleHealth(w, r)
		return
	}
	if pathHasSuffix(r.URL.Path, "/keys") || pathHasSuffix(r.URL.Path, "/jwks.json") || pathHasSuffix(r.URL.Path, "/.well-known/jwks.json") {
		s.handleJWKS(w, r)
		return
	}
	if prefix, botID, ok := matchEndpoint(r.URL.Path, "login"); ok {
		s.handleLogin(w, r, prefix, botID)
		return
	}
	if _, botID, ok := matchEndpoint(r.URL.Path, "auth/telegram"); ok {
		s.handleTelegramAuth(w, r, botID)
		return
	}
	s.notFound(w)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method == http.MethodHead {
		return
	}
	s.writeBytes(w, []byte(`{"ok":true}`), "health response")
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.methodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method == http.MethodHead {
		return
	}
	s.writeBytes(w, s.signer.JWKS(), "jwks response")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, prefix string, botID string) {
	if r.Method != http.MethodGet {
		s.methodNotAllowed(w, http.MethodGet)
		return
	}
	bot, ok := s.botsByID[botID]
	if !ok {
		if !s.allowRequest(w, r, s.loginLimits, "login_unknown", "unknown") {
			return
		}
		s.logger.Warn("login requested for unknown bot", requestAttrs(r, slog.String("bot_id", botID))...)
		s.notFound(w)
		return
	}
	if !s.allowRequest(w, r, s.loginLimits, "login", bot.ID) {
		return
	}
	if len(r.URL.RawQuery) > maxLoginQueryBytes {
		s.logger.Warn("login query too large", requestAttrs(r, slog.String("bot_id", botID), slog.Int("query_bytes", len(r.URL.RawQuery)))...)
		s.error(w, http.StatusRequestEntityTooLarge, "login request is too large")
		return
	}
	loginQuery, err := canonicalizeLoginQuery(r.URL.RawQuery)
	if err != nil {
		s.logger.Warn("invalid login query", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusBadRequest, "invalid login request")
		return
	}
	nonce, err := newNonce()
	if err != nil {
		s.logger.Error("create login nonce failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusInternalServerError, "could not create nonce")
		return
	}
	now := time.Now()
	state, err := signState(bot, loginQuery, nonce, now)
	if err != nil {
		s.logger.Error("create login state failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusInternalServerError, "could not create state")
		return
	}
	secureCookie := s.secureCookies(r)
	sessionID := loginSessionID(r, secureCookie)
	if sessionID == "" {
		sessionID, err = newNonce()
		if err != nil {
			s.logger.Error("create login session failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
			s.error(w, http.StatusInternalServerError, "could not create login session")
			return
		}
	}
	stateVerifier := stateCookieVerifier(state)
	switch s.pendingStates.add(sessionID, stateVerifier, now.Add(s.cfg.StateTTL), now) {
	case pendingStateAtCapacity:
		s.logger.Error("pending login state store at capacity", requestAttrs(r, slog.String("bot_id", botID))...)
		s.error(w, http.StatusServiceUnavailable, "login is temporarily unavailable")
		return
	case pendingStateSessionEvicted:
		s.logger.Warn("oldest pending login for session evicted", requestAttrs(r, slog.String("bot_id", botID))...)
	}
	cspNonce, err := newCSPNonce()
	if err != nil {
		s.pendingStates.consume(sessionID, stateVerifier, now)
		s.logger.Error("create CSP nonce failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusInternalServerError, "could not create login page")
		return
	}
	access := make([]string, 0, 2)
	if bot.RequestWrite {
		access = append(access, "write")
	}
	if bot.RequestPhone {
		access = append(access, "phone")
	}
	data := loginTemplateData{
		BotID:         bot.ID,
		BotName:       bot.Name,
		Lang:          bot.Lang,
		RequestAccess: access,
		Nonce:         nonce,
		State:         state,
		AuthAction:    joinURLPath(prefix, "auth/telegram", bot.ID),
		CSPNonce:      cspNonce,
	}
	var page bytes.Buffer
	if err := s.loginPage.Execute(&page, data); err != nil {
		s.pendingStates.consume(sessionID, stateVerifier, now)
		s.logger.Error("render login page failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusInternalServerError, "could not create login page")
		return
	}
	setLoginSessionCookie(w, sessionID, s.cfg.StateTTL, secureCookie)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	setLoginSecurityHeaders(w.Header(), cspNonce)
	s.writeBytes(w, page.Bytes(), "login page")
}

func (s *Server) handleTelegramAuth(w http.ResponseWriter, r *http.Request, botID string) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, http.MethodPost)
		return
	}
	bot, ok := s.botsByID[botID]
	if !ok {
		if !s.allowRequest(w, r, s.authLimits, "auth_unknown", "unknown") {
			return
		}
		s.logger.Warn("telegram auth posted for unknown bot", requestAttrs(r, slog.String("bot_id", botID))...)
		s.notFound(w)
		return
	}
	if !s.allowRequest(w, r, s.authLimits, "auth", bot.ID) {
		return
	}
	if hasAuthCredentialsInQuery(r.URL.Query()) {
		s.logger.Warn("telegram auth credentials sent in query string", requestAttrs(r, slog.String("bot_id", botID))...)
		s.error(w, http.StatusBadRequest, "auth credentials must be submitted in the form body")
		return
	}
	if !isFormURLEncoded(r.Header.Get("Content-Type")) {
		s.logger.Warn("telegram auth has unsupported content type", requestAttrs(r, slog.String("bot_id", botID))...)
		s.error(w, http.StatusUnsupportedMediaType, "unsupported content type")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthFormBytes)
	if err := r.ParseForm(); err != nil {
		s.logger.Warn("parse telegram auth form failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.error(w, http.StatusRequestEntityTooLarge, "auth request is too large")
		} else {
			s.error(w, http.StatusBadRequest, "invalid form body")
		}
		return
	}
	encodedState, err := requiredSingleFormValue(r.PostForm, "state")
	if err != nil {
		s.logger.Warn("telegram auth has invalid state field", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusBadRequest, "invalid state field")
		return
	}
	idToken, err := requiredSingleFormValue(r.PostForm, "id_token")
	if err != nil {
		s.logger.Warn("telegram auth has invalid id_token field", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusBadRequest, "invalid id_token field")
		return
	}
	now := time.Now()
	state, err := verifyState(bot, encodedState, now, s.cfg.StateTTL)
	if err != nil {
		s.logger.Warn("login state validation failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusBadRequest, "invalid login state")
		return
	}
	sessionID := loginSessionID(r, s.secureCookies(r))
	if sessionID == "" {
		s.logger.Warn("login state is not pending", requestAttrs(r, slog.String("bot_id", botID))...)
		s.error(w, http.StatusBadRequest, "invalid login state")
		return
	}
	if !s.pendingStates.consume(sessionID, stateCookieVerifier(encodedState), now) {
		s.logger.Warn("login state is not pending", requestAttrs(r, slog.String("bot_id", botID))...)
		s.error(w, http.StatusBadRequest, "invalid login state")
		return
	}
	user, err := s.telegram.Validate(r.Context(), idToken, bot.ID, state.Nonce)
	if err != nil {
		s.logger.Warn("telegram token validation failed", requestAttrs(r, slog.String("bot_id", botID))...)
		s.error(w, http.StatusUnauthorized, "invalid Telegram login")
		return
	}
	jwt, err := s.issueZitadelJWT(bot, user)
	if err != nil {
		s.logger.Error("issue zitadel jwt failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		s.error(w, http.StatusInternalServerError, "could not issue JWT")
		return
	}
	if err := s.proxyToZitadel(w, r, jwt, state.Query); err != nil {
		s.logger.Error("zitadel relay failed", requestAttrs(r, slog.String("bot_id", botID), slog.Any("error", err))...)
		return
	}
	s.logger.Info("telegram login relayed to zitadel", requestAttrs(r, slog.String("bot_id", botID))...)
}

func (s *Server) issueZitadelJWT(bot BotConfig, user TelegramUser) (string, error) {
	now := time.Now()
	expires := now.Add(s.cfg.JWT.TTL)
	if user.ExpiresAt > 0 {
		sourceExpiry := time.Unix(user.ExpiresAt, 0)
		if sourceExpiry.Before(expires) {
			expires = sourceExpiry
		}
	}
	expiresUnix := expires.Unix()
	if time.Unix(expiresUnix, 0).Sub(now) < minimumRelayLifetime {
		return "", errors.New("Telegram token expires too soon")
	}
	userID := user.Subject
	name := user.Name
	if name == "" {
		name = user.PreferredUsername
	}
	if name == "" {
		name = "Telegram user " + userID
	}
	username := user.PreferredUsername
	if username == "" {
		username = "tg_" + sanitizeLocalPart(userID)
	}
	jti, err := randomID()
	if err != nil {
		return "", fmt.Errorf("create jwt id: %w", err)
	}
	authTime := user.IssuedAt
	if authTime > now.Unix() {
		authTime = now.Unix()
	}
	claims := map[string]any{
		"iss":                             s.cfg.Issuer,
		"sub":                             "telegram:" + bot.ID + ":" + userID,
		"iat":                             now.Unix(),
		"nbf":                             now.Add(-5 * time.Second).Unix(),
		"exp":                             expiresUnix,
		"auth_time":                       authTime,
		"jti":                             jti,
		"name":                            name,
		"preferred_username":              username,
		"email":                           fakeEmail(bot.ID, userID, s.cfg.EmailDomain),
		"email_verified":                  s.cfg.SyntheticEmailVerified,
		"urn:zitadeltg:telegram:bot_id":   bot.ID,
		"urn:zitadeltg:telegram:bot_name": bot.Name,
		"urn:zitadeltg:telegram:subject":  userID,
	}
	claims["aud"] = s.cfg.JWT.Audience
	if user.Picture != "" {
		claims["picture"] = user.Picture
	}
	if bot.RequestPhone && user.PhoneNumber != "" {
		claims["phone"] = user.PhoneNumber
		claims["phone_verified"] = user.PhoneNumberVerified
		claims["phone_number"] = user.PhoneNumber
		claims["phone_number_verified"] = user.PhoneNumberVerified
	}
	return s.signer.Sign(claims)
}

func (s *Server) proxyToZitadel(w http.ResponseWriter, r *http.Request, jwt string, rawQuery string) error {
	target, err := url.Parse(s.cfg.Zitadel.JWTEndpoint)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "invalid ZITADEL endpoint")
		return fmt.Errorf("parse ZITADEL endpoint: %w", err)
	}
	if err := mergeZitadelQuery(target, rawQuery); err != nil {
		s.error(w, http.StatusInternalServerError, "invalid ZITADEL relay query")
		return err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "could not create ZITADEL request")
		return fmt.Errorf("create ZITADEL request: %w", err)
	}
	req.Header.Set(s.cfg.Zitadel.JWTHeader, jwt)
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := s.proxyClient.Do(req)
	if err != nil {
		s.error(w, http.StatusBadGateway, "could not call ZITADEL")
		return sanitizedRemoteError("call ZITADEL", target.String(), err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32*1024))
	if !isRedirectStatus(resp.StatusCode) {
		s.error(w, http.StatusBadGateway, "unexpected ZITADEL response")
		return fmt.Errorf("ZITADEL returned status %d", resp.StatusCode)
	}
	rawLocation := resp.Header.Get("Location")
	if rawLocation == "" {
		s.error(w, http.StatusBadGateway, "invalid ZITADEL redirect")
		return errors.New("ZITADEL redirect has no Location")
	}
	location, err := url.Parse(rawLocation)
	if err != nil {
		s.error(w, http.StatusBadGateway, "invalid ZITADEL redirect")
		return fmt.Errorf("parse ZITADEL Location failed (%s)", safeRemoteCause(err))
	}
	resolved := target.ResolveReference(location)
	if resolved.Scheme != "https" || resolved.Host == "" || resolved.User != nil {
		s.error(w, http.StatusBadGateway, "invalid ZITADEL redirect")
		return errors.New("ZITADEL redirect target must be an HTTPS URL without userinfo")
	}
	if !s.isAllowedRedirect(target, resolved) {
		s.error(w, http.StatusBadGateway, "invalid ZITADEL redirect")
		return errors.New("ZITADEL redirect origin is not allowed")
	}
	w.Header().Set("Location", resolved.String())
	w.Header().Set("Cache-Control", "no-store")
	// The browser posted Telegram credentials to this handler. Always switch to
	// GET so an upstream 307/308 can never resend that body to the destination.
	w.WriteHeader(http.StatusSeeOther)
	return nil
}

func (s *Server) isAllowedRedirect(target *url.URL, resolved *url.URL) bool {
	if s.cfg.Zitadel.AllowAnyRedirectOrigin {
		return true
	}
	origin := canonicalHTTPSOrigin(resolved)
	if origin == canonicalHTTPSOrigin(target) {
		return true
	}
	for _, allowed := range s.cfg.Zitadel.RedirectOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func (s *Server) allowRequest(w http.ResponseWriter, r *http.Request, limiter *requestLimiter, scope string, botID string) bool {
	client := s.clientIP(r)
	key := scope + "|" + botID + "|" + client
	now := time.Now()
	allowed, retryAfter, capacityLimited := limiter.allow(key, now)
	if allowed {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	message := "request rate limit exceeded"
	if capacityLimited {
		message = "request rate limiter at capacity"
	}
	logAllowed, _, _ := s.rateLimitLogs.allow("rate-limit-denial", now)
	if logAllowed {
		s.logger.Warn(message, requestAttrs(r,
			slog.String("scope", scope),
			slog.String("bot_id", botID),
			slog.Int("retry_after_seconds", retryAfter),
		)...)
	}
	s.error(w, http.StatusTooManyRequests, "too many requests")
	return false
}

func (s *Server) clientIP(r *http.Request) string {
	return clientIP(r, s.cfg.Proxy.TrustedCIDRs)
}

func (s *Server) secureCookies(r *http.Request) bool {
	return s.cfg.Proxy.SecureCookies || isSecureRequest(r, s.cfg.Proxy.TrustedCIDRs)
}

type loginTemplateData struct {
	BotID         string
	BotName       string
	Lang          string
	RequestAccess []string
	Nonce         string
	State         string
	AuthAction    string
	CSPNonce      string
}

func templateJSON(v any) (template.JS, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return template.JS(data), nil
}

func isFormURLEncoded(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "application/x-www-form-urlencoded")
}

func canonicalizeLoginQuery(rawQuery string) (string, error) {
	if rawQuery == "" {
		return "", nil
	}
	// ZITADEL requires every callback parameter to be copied back. Preserve
	// arbitrary parameter names while rejecting malformed encodings and
	// duplicates, then sign a deterministic encoding rather than RawQuery.
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	for key, value := range values {
		if key == "" {
			return "", errors.New("query parameter name is empty")
		}
		if len(value) != 1 {
			return "", fmt.Errorf("query parameter %q must occur exactly once", key)
		}
	}
	return values.Encode(), nil
}

func mergeZitadelQuery(target *url.URL, rawQuery string) error {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return fmt.Errorf("parse signed ZITADEL query: %w", err)
	}
	targetQuery := target.Query()
	for key, value := range values {
		if key == "" || len(value) != 1 {
			return fmt.Errorf("signed ZITADEL query parameter %q is invalid", key)
		}
		if targetQuery.Has(key) {
			return fmt.Errorf("signed ZITADEL query conflicts with configured parameter %q", key)
		}
		targetQuery.Set(key, value[0])
	}
	target.RawQuery = targetQuery.Encode()
	return nil
}

func hasAuthCredentialsInQuery(values url.Values) bool {
	return values.Has("id_token") || values.Has("state")
}

func requiredSingleFormValue(values url.Values, name string) (string, error) {
	items := values[name]
	if len(items) != 1 || items[0] == "" {
		return "", fmt.Errorf("%s must occur exactly once and be non-empty", name)
	}
	return items[0], nil
}

func pathHasSuffix(requestPath string, suffix string) bool {
	cleanPath := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	return cleanPath == suffix || strings.HasSuffix(cleanPath, suffix)
}

func matchEndpoint(requestPath string, endpoint string) (prefix string, id string, ok bool) {
	cleanPath := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	marker := "/" + endpoint + "/"
	idx := strings.LastIndex(cleanPath, marker)
	if idx < 0 {
		return "", "", false
	}
	id = cleanPath[idx+len(marker):]
	if id == "" || strings.Contains(id, "/") {
		return "", "", false
	}
	return cleanPath[:idx], id, true
}

func joinURLPath(prefix string, parts ...string) string {
	all := []string{prefix}
	all = append(all, parts...)
	joined := path.Join(all...)
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

var (
	localPartRe    = regexp.MustCompile(`[^a-z0-9_.+-]+`)
	dotRunRe       = regexp.MustCompile(`\.+`)
	requestIDLogRe = regexp.MustCompile(`^[0-9a-fA-F-]{16,64}$`)
)

func fakeEmail(botID string, userID string, domain string) string {
	local := "tg+" + sanitizeLocalPart(botID) + "+" + sanitizeLocalPart(userID)
	digest := sha256.Sum256([]byte(botID + "\x00" + userID))
	suffix := "+" + base64.RawURLEncoding.EncodeToString(digest[:12])
	if len(local) > 64-len(suffix) {
		local = local[:64-len(suffix)]
	}
	local = strings.TrimRight(local, ".-+_") + suffix
	return local + "@" + strings.ToLower(domain)
}

func sanitizeLocalPart(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "@")
	value = localPartRe.ReplaceAllString(value, "-")
	value = dotRunRe.ReplaceAllString(value, ".")
	value = strings.Trim(value, ".-+_")
	if value == "" {
		return "unknown"
	}
	return value
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func newCSPNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b[:]), nil
}

func setCommonSecurityHeaders(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("Strict-Transport-Security", "max-age=31536000")
}

func setLoginSecurityHeaders(header http.Header, nonce string) {
	header.Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
	header.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"script-src 'nonce-" + nonce + "' https://oauth.telegram.org",
		"style-src 'nonce-" + nonce + "'",
		"connect-src https://oauth.telegram.org",
		"frame-src https://oauth.telegram.org",
		"img-src 'none'",
	}, "; "))
}

func setLoginSessionCookie(w http.ResponseWriter, sessionID string, ttl time.Duration, secure bool) {
	maxAge := int((ttl + time.Second - 1) / time.Second)
	http.SetCookie(w, &http.Cookie{
		Name:     loginSessionCookieName(secure),
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func loginSessionID(r *http.Request, secure bool) string {
	cookie, err := r.Cookie(loginSessionCookieName(secure))
	if err != nil {
		return ""
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != cookie.Value {
		return ""
	}
	return cookie.Value
}

func loginSessionCookieName(secure bool) string {
	if secure {
		return secureSessionCookieName
	}
	return insecureSessionCookieName
}

func stateCookieVerifier(state string) string {
	digest := sha256.Sum256([]byte("zitadeltg-state-cookie\x00" + state))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func requestAttrs(r *http.Request, attrs ...slog.Attr) []any {
	out := []any{
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if requestID := r.Header.Get("X-Request-ID"); requestIDLogRe.MatchString(requestID) {
		out = append(out, slog.String("request_id", requestID))
	}
	for _, attr := range attrs {
		out = append(out, attr)
	}
	return out
}

func (s *Server) writeBytes(w http.ResponseWriter, data []byte, label string) {
	if _, err := w.Write(data); err != nil {
		s.logger.Error("write response failed", slog.String("response", label), slog.Any("error", err))
	}
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	s.error(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Server) notFound(w http.ResponseWriter) {
	s.error(w, http.StatusNotFound, "404 page not found")
}

func (s *Server) error(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if w.Header().Get("Content-Security-Policy") == "" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	}
	w.WriteHeader(status)
	s.writeBytes(w, []byte(message+"\n"), http.StatusText(status))
}
