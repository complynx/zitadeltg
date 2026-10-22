# Telegram prelink hook

The optional hook lets an application reconcile its canonical account and exact
Zitadel provider link before zitadeltg completes a verified Telegram login. It is
configured separately for each bot. Omitted or entirely empty `prelink` settings
preserve the existing flow. Partial or unsafe settings fail startup.

```yaml
bots:
  - token: "${TELEGRAM_BOT_MAIN}"
    name: main_example_bot
    prelink:
      endpoint: https://backend.example.com/internal/identity/telegram-prelink
      audience: application-telegram-prelink
      service_bearer: "${TELEGRAM_PRELINK_SERVICE_KEY}"
      organization_id: "ORGANIZATION_ID"
      provider_id: "PROVIDER_ID"
```

Generate a dedicated random 32-byte secret encoded as unpadded base64url. Do not
reuse a Telegram or IAM credential. The audience must differ from `jwt.audience`.
The endpoint must use verified HTTPS, the exact path shown above, and no userinfo,
query or fragment. The configured organization and provider are expected receipt
values; they are not browser-selectable targets.

## Assertion contract

After validating browser state and the Telegram signature, issuer, bot audience,
nonce and freshness, zitadeltg sends:

```http
POST /internal/identity/telegram-prelink
Authorization: Bearer SERVICE_SECRET
Content-Type: application/json

{"assertion":"COMPACT_RS256_JWT"}
```

The assertion uses the existing signing key, `kid`, issuer and public JWKS. Its
audience is the bot's prelink audience, not the IAM relay audience. It includes:

| Claim | Value |
| --- | --- |
| `sub` | `telegram:BOT_ID:OPAQUE_TELEGRAM_SUBJECT` |
| `jti` | A fresh intent identifier |
| `iat`, `nbf`, `exp` | Issue time, five-second nbf allowance, strict expiry |
| `urn:zinusya:purpose` | `telegram-prelink` |
| `urn:zitadeltg:telegram:bot_id` | Canonical decimal bot ID string |
| `urn:zitadeltg:telegram:user_id` | Canonical decimal numeric Telegram ID string |
| `urn:zitadeltg:telegram:subject` | The actual opaque Telegram subject |
| `email` | `tg+BOT_ID+NUMERIC_ID@telegram.invalid` |
| `email_verified` | `true` for this reserved identifier |
| `given_name`, `family_name`, `preferred_username` | Verified profile metadata |

The purpose claim name and wire fields preserve the existing Zinusya consumer
contract described in issue #10. They are intentional protocol names, not a
dependency on that application's implementation.

An assertion lasts at most 60 seconds and never outlives its Telegram proof.
At least five seconds of source lifetime must remain before starting backend
work. Profile fields are valid UTF-8, at most 200 bytes each, and contain no
control characters. Identity/configuration fields have a 200-byte bound and do
not permit whitespace or control characters. The complete namespaced subject
must fit the same bound.

The backend must independently verify the service credential, RS256 signature,
pinned issuer/JWKS, audience, purpose, times, numeric ID and opaque subject.
Treat this assertion as verified identity evidence, not permission to merge an
arbitrary account or grant a role.

## Completion receipt

Only HTTP `200` with a valid JSON completion receipt permits the IAM relay:

```json
{
  "state": "completed",
  "operation_id": "11111111-1111-4111-8111-111111111111",
  "assertion_sha256": "LOWERCASE_SHA256_OF_EXACT_COMPACT_ASSERTION",
  "issuer": "https://accounts.example.com/tg",
  "assertion_jti": "ASSERTION_JTI",
  "bot_id": 123456789,
  "telegram_user_id": 777000,
  "external_subject": "OPAQUE_TELEGRAM_SUBJECT",
  "user_id": "22222222-2222-4222-8222-222222222222",
  "subject": "ZITADEL_USER_ID",
  "organization": "ORGANIZATION_ID",
  "provider_id": "PROVIDER_ID",
  "expires_at": "ASSERTION_EXP_AS_RFC3339"
}
```

All fields are mandatory. Unknown fields, duplicate names, case aliases, null or
incorrectly typed required values, trailing JSON and responses over 16 KiB are
rejected. Operation and application-user IDs must be nonzero UUIDs. The IAM
subject must be nonempty and bounded. The digest, issuer, JTI, identity tuple,
organization and provider must match this exact assertion and configuration.
`expires_at` must equal the assertion expiry and still be in the future.

The receipt is trusted only as the authenticated backend's HTTPS response to this
request. It contains no IAM access token. zitadeltg does not use its `subject` to
choose or impersonate an IAM user: the normal JWT IdP flow still resolves the
verified external subject.

## Backend responsibilities and retries

The backend owns canonical-account provisioning, account authorization, exact
organization/provider linking and durable reconciliation. It must serialize or
otherwise reconcile concurrent bot/Mini App and provider entry points. Read back
the active account and exact provider link before acknowledging completion.
Revalidate current authority even when replaying a persisted completion; a cached
receipt must not bypass revocation or a conflicting binding.

The hook sends no browser cookies and follows no redirects. Each request is
bounded to three seconds; at most three attempts share an eight-second total
budget, also bounded by assertion/source expiry and browser cancellation.
Transport/read failures and HTTP 5xx can retry after 150 ms. Every retry uses the
identical assertion bytes, JTI and JSON body. Denials, conflicts, redirects and
invalid receipts do not retry. A `pending` receipt never permits relay.

Browser state is consumed before proof validation and hook execution, as in the
existing flow. Reposting that browser callback does not retry the hook. A fresh
browser login or process restart creates a new intent; the backend must converge
on the same canonical account using its durable identity mapping.

Denial returns `403`; unavailable or invalid completion returns `503`. In both
cases IAM relay is withheld. If the Telegram proof expires or becomes unusable
after completion, the existing relay lifetime checks still withhold the relay.
Backend completion is not undone by a lost response, cancellation or relay error.

Only opted-in bots use verified `telegram.invalid` relay identifiers. Other bots
retain the global email-domain and verification policy. For opted-in bots,
Telegram claim dumps and IAM response/JWT dumps are suppressed even at debug
level. Hook secrets, assertions, receipts and personal claim values are not logged.

## Verification boundary

Component tests cover configuration, authenticated proof, receipts, identical
retries, cancellation, expiry, metadata bounds and fail-closed errors. The Docker
suite exercises real Zitadel provisioning/linking, both entry orders, concurrent
first entry, lost replies, sequential login and completed-login process restart,
then completes and verifies OIDC/PKCE.

The integration backend is a test fixture, not the Zinusya production backend.
It checks the upstream contract and IAM behavior. Durable application storage,
application-specific authorization/revocation and real Telegram acceptance remain
the consumer's responsibility. This feature does not activate a provider or change
production settings.
