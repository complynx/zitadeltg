# Zitadel compatibility tests

Run the pinned version from `docker-compose.yml` with Docker Compose v2:

```sh
bash integration/run.sh
```

On Windows with Docker Desktop:

```powershell
pwsh -File integration/run.ps1
```

The scripts build the service, create an isolated Compose project, run the suite
with Go's race detector, and remove that project's containers, network and volumes
on exit. No host ports or production credentials are used. A failed test returns
a non-zero exit code and prints Zitadel/PostgreSQL logs. The Go tests have a
12-minute timeout; the CI job has a 20-minute timeout.

`docker-compose.yml` contains a literal, pinned Zitadel image tag. Dependabot's
`docker-compose` entry updates that tag and opens a PR. The `Zitadel compatibility`
workflow runs the new image on each PR, including Dependabot PRs. Configure branch
protection to require `Zitadel compatibility / integration` before merging version
updates. An update is tested; it is not automatically deployed.

PostgreSQL uses the production `pgvector/pgvector` image, pinned by digest to
PostgreSQL 17.9 (verified on 2026-10-22). Dependabot ignores this image. Update
the digest manually when the production PostgreSQL version changes.

To check another exact version without changing the pin, create an override:

```yaml
services:
  zitadel:
    image: ghcr.io/zitadel/zitadel:v4.16.3
```

Run Compose with both files and a fresh project name, using the same lifecycle as
`run.sh`. Always use `run --rm --use-aliases suite`: the HTTPS hostname `idp.test`
is a network alias of the suite. Reusing a database also reuses test fixtures;
each full run must start with fresh volumes.

## Test boundary

PostgreSQL and Zitadel are real containers. The suite launches the compiled
`zitadeltg` executable with a YAML configuration and a persistent RSA key. A Go
HTTPS gateway routes `/tg/` to that process and other paths to Zitadel, preserving
the host and setting the trusted HTTPS forwarding header. This models production's
same-host Login V1 setup. It uses fresh test CA and System API keys generated before
Zitadel starts. Certificate verification remains enabled on every TLS connection.

The suite provisions a tenant, OIDC client, JWT providers and users through
Zitadel's public APIs. It waits separately for server readiness, the System API,
and the tenant's OIDC discovery endpoint. Fixtures do not write directly to
Zitadel's database. The test configuration permits private-network JWKS calls;
this exception belongs only to this isolated test stack.

The fake Telegram authority serves JWKS and signs controlled identity tokens.
The HTTP test browser uses a cookie jar, follows the real login forms and submits
the Telegram callback. Successful login tests require an authorization code,
exchange it using PKCE, verify the resulting ID token's signature, issuer,
audience, expiry and nonce, and check its subject against `userinfo`.

Coverage includes:

- Manual registration with edited names; returning users and persisted IdP links.
- Automatic creation, verified synthetic email, normalized phone, single-name
  profiles, and string-valued Telegram IDs.
- Profile updates enabled and disabled; stable identity after username changes.
- Isolation of identical Telegram subjects across bots and optional phone scopes.
- Email auto-linking to a pre-imported user; disabled auto-linking; manual linking
  after authenticating the existing account.
- Matching and mismatching relay audiences and the empty-audience behavior.
- Providers that allow neither account creation nor linking.
- Invalid Telegram issuer, audience, nonce, signature, expiry, issued-at,
  subject and numeric ID; insufficient remaining token lifetime. Invalid tokens
  must not reach the Zitadel callback.
- Single-use state after success and failure, browser-cookie binding, missing
  Zitadel user-agent cookies, unknown bots and duplicate callback parameters.
- Process restart: the signing key survives, pending states do not, and a fresh
  authentication still succeeds.
- Required email verification and MFA fail closed. The current relay returns
  `502` for these upstream HTML pages; tests check the email diagnostic category
  and the upstream MFA form.
- Incorrect relay issuer/header and the configured authentication rate limit.

The suite covers the server-side Login V1 integration. It does not execute the
external Telegram JavaScript, real Telegram consent, Login V2, email delivery,
SMS delivery, MFA enrollment or a production database upgrade. The existing unit
suite covers additional parser, proxy, redirect, logging and key-file edge cases.

The suite also records the current `500` response when a valid Telegram token
has too little remaining lifetime to issue a relay JWT. This is a local rejection;
the token must not reach Zitadel. The response is not classified as a Telegram
validation failure by the current service.
