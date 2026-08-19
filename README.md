# zitadeltg

Telegram Login to ZITADEL through a ZITADEL JWT IdP.

The service renders `/login/BOT_ID`, validates Telegram Login `id_token` values
server-side against Telegram JWKS, issues a short-lived RSA-signed JWT, and
proxies the browser back to ZITADEL's JWT IdP callback with that JWT in the
configured header.

## Endpoints

- `GET /login/BOT_ID` renders the Telegram Login page. `BOT_ID` must match one
  configured `BOT_ID:BOT_SECRET` token.
- `POST /auth/telegram/BOT_ID` receives the Telegram Login library callback
  token and relays the signed JWT to ZITADEL.
- `GET /keys`, `/jwks.json`, and `/.well-known/jwks.json` return the public
  JWKS ZITADEL uses to verify JWT signatures.
- `GET /healthz` returns a simple health response.

Routes are suffix-matched, so the same service also works behind path prefixes
such as `/tg/login/BOT_ID` and `/tg/keys` when a proxy does not strip the prefix.
ZITADEL's callback query parameters are strictly parsed, duplicate names are
rejected, and the canonicalized query is signed before it is relayed. The
service accepts redirect responses from ZITADEL and one narrowly recognized
ZITADEL v4.15 manual-registration form; all other upstream HTML and error bodies
are rejected. Every accepted redirect is returned as `303 See Other`, so the
browser never forwards the credential-bearing POST.
Same-origin ZITADEL redirects are accepted automatically. Add every permitted
cross-origin application origin to `zitadel.redirect_origins`; scheme, host, and
non-default port are matched exactly. `zitadel.allow_any_redirect_origin: true`
delegates all redirect policy to ZITADEL and should be used only when ZITADEL's
application redirect allowlists are the sole intended enforcement point.

## Configuration

Copy `config.example.yaml` to `config.yaml` and put each Telegram token in its
own environment variable:

```sh
export TELEGRAM_BOT_MAIN='123456789:client-secret-from-botfather'
export TELEGRAM_BOT_SUPPORT='987654321:client-secret-from-botfather'
go run ./cmd/zitadeltg -config config.yaml
```

YAML placeholders use `${VAR}` or `${VAR:-default}`. Missing `${VAR}` values are
treated as startup errors so bot secrets are not silently blank.

`issuer`, `public_url`, `zitadel.jwt_endpoint`, `telegram.issuer`, and
`telegram.jwks_url` must be absolute HTTPS URLs. `jwt.ttl` must be between `6s`
and `15m`, and `state_ttl` is capped at `30m`. JWT assertions always include an
audience; when `jwt.audience` is omitted it defaults to
`zitadel.jwt_endpoint`.

`public_url` is the canonical external identity used as the default `issuer`;
it does not constrain general route matching. Relaying the manual-registration
form additionally requires the actual request `Host`, `public_url`, and the
ZITADEL callback to have the same HTTPS origin.

`zitadel.user_agent_cookie` defaults to ZITADEL v4.15.0's secure external
cookie name, `__Host-zitadel.useragent`. The relay forwards only this cookie to
ZITADEL so the server-side JWT callback retains the browser auth request's
user-agent binding. If `UserAgentCookie.Name` is customized in ZITADEL, set the
same name here. Because `__Host-` cookies are host-only, Login V1 requires
zitadeltg to be exposed under the same HTTPS hostname as ZITADEL, normally under
a dedicated path prefix. A different hostname cannot receive this browser
cookie. The relay checks secure same-host provenance and forwards no other
incoming cookies.

`synthetic_email_verified` defaults to `false`. ZITADEL Login V1 requires a
verified email before it completes authentication, so deployments using
automatic external-user creation can set it to `true`. This opt-in is accepted
only when `email_domain` is a subdomain of the reserved `invalid` domain, such
as `telegram.invalid`. Keep email-based automatic linking disabled: these
addresses are stable synthetic identifiers, not deliverable mailboxes.

If `jwt.private_key_file` is omitted, it defaults to `/data/zitadeltg-rsa.pem`. When
the configured key file does not exist, the service creates a 2048-bit RSA key
with `0600` permissions, publishes it atomically without replacing an existing
key, and reuses it on later starts. Mount the key file or its containing
directory as persistent storage in Docker so ZITADEL keeps verifying JWT
signatures across restarts.

All replicas for one issuer must mount the same private key and use the same
`jwt.key_id`. Do not let replicas generate independent keys under one issuer and
key ID, because their JWKS responses and signed tokens would disagree.

When running behind Traefik, set `proxy.trusted_cidrs` to the Traefik container
or network CIDRs that are allowed to supply `X-Forwarded-For`,
`X-Forwarded-Proto`, and `Forwarded`. Keep this list narrow; untrusted clients
must not be able to choose their own forwarded headers. `secure_cookies`
defaults to `true`, which is appropriate for TLS termination at Traefik.
Configure the trusted proxy to overwrite untrusted forwarding headers or append
its authoritative value last; the service evaluates the rightmost scheme value
from the nearest trusted hop. `X-Forwarded-For` determines client identity;
`X-Forwarded-Proto` and `Forwarded` determine the scheme. `X-Real-IP` and
`Forwarded for=` are not used for client identity.

The built-in per-client, per-bot limits default to:

```yaml
rate_limit:
  login:
    requests: 60
    window: "1m"
  auth:
    requests: 20
    window: "1m"
```

Set a bucket's `requests` to `0` to disable it, or prefer Traefik's own rate
limit middleware if you need distributed limits across multiple replicas.
The in-process limiter and pending-state store are each bounded at 100,000
entries and fail closed at capacity. For an internet-facing deployment, enforce
an aggregate admission limit at the edge and alert on sustained login `503` or
rate-limit `429` responses; rotating source identities can otherwise consume
per-process capacity even though memory remains bounded.

## Docker

The container runs as a non-root user, listens on port `8080`, and uses `/data`
as its working directory. The example below keeps generated keys in a named
volume, mounts the configuration read-only, and explicitly passes the bot
environment variables into the container:

```sh
docker volume create zitadeltg-data
docker run --rm -p 8080:8080 \
  --env TELEGRAM_BOT_MAIN \
  --env TELEGRAM_BOT_SUPPORT \
  --mount type=bind,src="$PWD/config.yaml",dst=/config/config.yaml,readonly \
  --mount type=volume,src=zitadeltg-data,dst=/data \
  complynx/zitadeltg:latest -config /config/config.yaml
```

If you use a bind mount for `/data` instead, make it writable by the container's
non-root `zitadeltg` user before startup.

Linux is the supported production runtime and is the platform on which the
no-follow key open, atomic no-replace publication, and directory durability
guarantees are enforced. Non-Linux builds are not production-supported.
Windows key persistence is explicitly unsupported and startup fails with a
platform error rather than silently applying POSIX permission assumptions.

For each bot:

- `token` is `BOT_ID:BOT_SECRET`.
- `name` is displayed on the login page and included in the bot-name claim.
- `write` requests permission for direct messages.
- `phone` requests the verified phone number claim.

The fake email format uses a readable form of Telegram's OIDC `sub` plus a
collision-resistant digest of the original bot/subject pair:

```text
tg+BOT_ID+SANITIZED_SUBJECT+DIGEST@email_domain
```

Synthetic addresses are sent with the configured `synthetic_email_verified`
value; configure ZITADEL to identify users by `sub`, not by matching these
addresses to existing accounts.
The digest prevents different subjects that sanitize to the same text from
sharing an address. The service does not use Telegram's optional custom `id`
claim for identity.

The relay preserves Telegram's standard `given_name` and `family_name` claims
for ZITADEL user creation. If Telegram omits either claim, the service derives
it from `name`; a single-name profile uses the same value for both fields
because ZITADEL v4.15.0 requires both fields during external-user registration.

## ZITADEL Setup

Create a JWT IdP in ZITADEL with:

- Issuer: the configured `issuer`.
- Header name: the configured `zitadel.jwt_header`.
- Keys endpoint: the public zitadeltg keys route, for example
  `https://accounts.example.com/tg/keys`.
- JWT endpoint: the public zitadeltg login route, for example
  `https://accounts.example.com/tg/login/BOT_ID`.
- Audience: the configured `jwt.audience` (by default the value of
  `zitadel.jwt_endpoint`).

If `synthetic_email_verified` is enabled, disable email-based automatic linking
on the ZITADEL identity provider. Resolve users by the external issuer and
`sub`; the asserted email is synthetic and proves no mailbox ownership.

For new users to review and edit their Telegram-supplied first and last names,
enable manual account creation but disable **Automatic creation** on the JWT
provider. ZITADEL then returns its registration form, prefilled from
`given_name` and `family_name`; the relay serves that recognized form only when
the configured ZITADEL callback, `public_url`, and actual request host share the
same HTTPS origin. The form submission goes directly back to ZITADEL. The
shared virtual host must route `/ui/login/externaluser/option` and ZITADEL's
referenced `/ui/login/resources/` assets to ZITADEL, while routing only the
configured zitadeltg prefix to this service. Preserve the original `Host` and
supply HTTPS forwarding headers only from a proxy in `proxy.trusted_cidrs`.

Set `zitadel.jwt_endpoint` in this service to the ZITADEL login callback:

- Login V2: `https://accounts.example.com/idps/jwt`
- ZITADEL v4.15.0 Login V1: `https://accounts.example.com/ui/login/login/jwt/authorize`

## Telegram Setup

In `@BotFather` open `Bot Settings > Web Login`, add every public origin that
will host `/login/BOT_ID`, and copy the Client ID and Client Secret into the
per-bot environment variable.

Telegram's Login library requires the page origin to be allowed in BotFather. If
a proxy sets `Cross-Origin-Opener-Policy: same-origin`, change it to
`same-origin-allow-popups` or remove it for this page so the popup can return
the login result.

Before releasing, smoke-test a complete browser login from a registered origin
against Telegram's current `telegram-login.js?3`; unit tests verify the rendered
integration contract but cannot detect a breaking change in that external
script.

## Security Notes

The login page sets a nonce-based Content Security Policy and binds each signed
state to a bounded, server-side pending-state store through one HttpOnly,
SameSite session cookie. A state is single-use. The store is process-local, so
multi-replica deployments must use sticky routing for each login flow or replace
it with a shared store. Every callback attempt consumes its state, including an
attempt whose Telegram token fails validation. The callback accepts Telegram
`id_token` values only from an `application/x-www-form-urlencoded` POST body, so
tokens are not accepted from query strings. Startup fails if Telegram's JWKS
cannot be fetched, so deployment issues do not silently turn into login-time
verification failures.

Logs are emitted with Go `slog` in text format. `log_level` accepts Go slog
levels such as `debug`, `info`, `warn`, and `error`, and defaults to `info`.
At normal levels, validation failures include finite failure categories, while
JWKS refresh failures and ZITADEL relay errors remain sanitized. These records
do not include Telegram user IDs, IP addresses, ID tokens, or bot secrets.

At `debug`, the service also records request completion status, response size
and duration; safe authentication-stage milestones; JWKS initialization; and
ZITADEL relay metadata. Logs use finite route labels instead of raw request
paths. Request paths and query strings, client IP addresses, Telegram ID
tokens, bot tokens, state values, and session cookies are not logged.

For a failed ZITADEL relay, `log_level: debug` may additionally log the ZITADEL
response body (bounded to 32 KiB) and the generated relay JWT as
`jwt_unsigned=header.payload`. The dedicated field omits the signature, and
compact JWTs reflected in the upstream body are redacted on a best-effort
basis, but unsigned claims and the remaining response can contain identity or
session data. Enable debug only for a short reproduction, restrict access to
the logs, then restore `info` and delete the diagnostic log. Registration-shaped
responses and their JWTs are never included, whether relayed or rejected.

The login page loads Telegram's official Login library from
`oauth.telegram.org`; that script is therefore part of the authentication trust
boundary and receives the login nonce and Telegram result.
