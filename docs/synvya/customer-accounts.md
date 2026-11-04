# Customer Accounts

Passwordless customer accounts in Keycast: sign-in by email link, a commerce permission that lets an orders app place orders for a customer with one merchant and nothing else, and the fixes Keycast needed before holding customer keys.

**Reality:** **Built** in PR [#100](https://github.com/Synvya/keycast/pull/100) (not merged), including §10's merchant binding ([#102](https://github.com/Synvya/keycast/issues/102)). This document describes what was built; where the build differed from the first version of this spec, the built version is what is written here.

**Issues:** milestone [Orders: customer accounts](https://github.com/Synvya/keycast/milestone/3) — #88 to #98, #101, #102. Each section names its issue.

**System context:**
- [Cross-repo: Customer Accounts](https://github.com/Synvya/docs/blob/main/02-auth-and-identity/architecture/customer-accounts.md) — who does what across the orders app, Keycast and Synvya Server. **The orders app team works from that document.**
- [Orders PRD](https://github.com/Synvya/docs/blob/main/06-domains-and-services/specs/prd-orders.md) §8 and §13 (`[OR-8]`, `[OR-19]` – `[OR-22]`).
- [Order of work](https://github.com/Synvya/docs/blob/main/02-auth-and-identity/internal/todo-keycast-customer-accounts.md).

**Verified against:** `alejandro-dev` at `e145dac` (2026-11-03). The running-server checks (`tests/qa`, the scripted flows) were last run at `a4c5890`, before #102; the staging checks in §12 are #102's first run on a server.

---

## 0. Branch and PR

All of this work is on `alejandro-dev` and ships as one PR, #100, to `synvya-staging`. Keycast rollouts are slow, so the issues ship together. At least one commit per issue, with `Fixes #<n>`. Nothing goes upstream to `divinevideo/keycast`.

**Generic by design.** This serves any merchant that sells through Synvya's orders app. No merchant's name, domain or prices belong in code, config defaults or tests; examples use `orders.example.com`.

---

## 1. The two hostnames

Keycast decides which tenant a request belongs to from its hostname.

| Tenant | Production | Staging | Who uses it |
|---|---|---|---|
| Restaurant owners (existing) | `auth.synvya.com` | `auth.staging.synvya.com` | Synvya Restaurants, Synvya Server, admins |
| **Customers** (new) | `b2b-auth.synvya.com` | `b2b-auth.staging.synvya.com` | Every merchant's orders app, in the background. Customers never see it |

The same email can be an owner and a customer: two unrelated accounts, one per tenant. Each merchant's orders app lives at its own `orders.<merchant-domain>` and calls the customer hostname.

**Settings.** `CUSTOMER_TENANT_DOMAIN` names the customer hostname. It is set per environment in `scripts/load-secrets.sh`, next to `DOMAIN`, and is not a secret: the hostname is public. The script also writes `ALLOWED_TENANT_DOMAINS`. Keycast creates the customer tenant at startup. **While the setting is empty, customer accounts are off** and owners are unaffected. It is set on staging and empty on production. Turning it on is §14.

---

## 2. The cleanup job keeps passwordless accounts — #88

`spawn_cleanup_task` (`api/src/bcrypt_queue.rs`) deletes abandoned password sign-ups: rows whose bcrypt hash never arrived. It now also requires `email_verification_token IS NOT NULL`. `register` is the only production path that leaves `password_hash` NULL on a row with an email, and it always sets that token; customer accounts never have one. So customer accounts and their keys survive.

---

## 3. Email-link sign-in

### 3.1 Tokens — `magic_link_tokens`

```sql
CREATE TABLE magic_link_tokens (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL,
    email         VARCHAR(255) NOT NULL,      -- trim + lowercase
    token_hash    CHAR(64) NOT NULL UNIQUE,   -- sha256 of the token, hex
    purpose       VARCHAR(20) NOT NULL DEFAULT 'sign_in',   -- or 'delete_account' (§9)
    app_origin    TEXT NOT NULL,              -- the orders app the link lands on
    expires_at    TIMESTAMPTZ NOT NULL,       -- 15 minutes
    consumed_at   TIMESTAMPTZ,
    request_ip    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

The token is `generate_secure_token` (64 alphanumeric characters). Only its hash is stored. `consume` is one `UPDATE … RETURNING`, so a link works once even under concurrent clicks. Old rows are purged on the cleanup schedule. Code: `core/src/repositories/magic_link_token.rs`.

### 3.2 `POST /api/auth/magic-link` — request a link — #89

```json
{ "email": "dana@example.com", "app_url": "https://orders.example.com/signin", "purpose": "sign_in" }
```

`purpose` is optional (`sign_in` by default; `delete_account` is §9).

1. **Customer hostname only.** Elsewhere it is 404, or owners could sign in without their password.
2. **The app must be on the approved list.** The origin of `app_url` (scheme, host, port; any path is fine) must be a row in `customer_app_origins` (§10). Otherwise 400 and no email. The row also gives the merchant name the email uses.
3. **Throttles** (`api/src/rate_limit.rs`, Redis `incr_with_ttl`): one link per email per purpose per minute, five per email per hour, and `RATE_LIMIT_IP_PER_HOUR` per IP (default 60). The client IP is the last `X-Forwarded-For` entry, the one the load balancer appends; without that header the IP limit does not apply. A throttled request still answers `{ "success": true }` and sends nothing.
4. Store the token and send the email in the background, so timing does not reveal whether an email went out.
5. **Create nothing.** The account is created when the link is clicked.

Response, always: `{ "success": true }`.

**Email.** `send_magic_link_email` and `send_delete_account_email` on `EmailSender` (`api/src/email_service.rs`). Subject "Sign in to <merchant name>". The body never mentions Keycast, Synvya, keys or Nostr. **The From line is still the configured sender (`FROM_NAME=Synvya`, `noreply@synvya.com`)** until the open decision on per-merchant senders is made.

### 3.3 `POST /api/auth/magic-link/verify` — sign in — #90

The orders app's landing page reads `token` from its URL and posts it. POST only: email scanners open links with GET, and a GET consumes nothing.

```json
{
  "token": "…",
  "client_id": "orders.example.com",
  "redirect_uri": "https://orders.example.com/signin",
  "scope": "policy:commerce_envelope",
  "merchant_pubkey": "<hex, optional>",
  "local_key": "<hex secret key, optional>"
}
```

`client_id`, `redirect_uri` and `scope` come together or not at all. `merchant_pubkey` is optional: Keycast takes the merchant from the approved list (§10), and a different one is refused. Together they are the **grant**: permission for this app to place orders for the customer.

1. Consume the token for this tenant. Unknown, used, expired and other-tenant tokens all get the same 400.
2. **New email:** create the user (verified, no password) and a key. If `local_key` is a valid secret key, store it as the key instead (the Synvya Diners claim case). **Existing email:** use the existing key and ignore `local_key`. A key is never replaced.
3. **With a grant:** create the app's authorization under the merchant's `commerce_envelope` policy (§4). The session is that authorization's token, so it can sign at once through `/api/nostr`. This decrypts the customer's key once, because the authorization's key is derived from it.
4. **Without a grant:** a server-signed session that identifies the customer but **cannot sign**. Use it only for the account page.
5. No response contains a pubkey, npub or key material.

```json
{ "success": true, "session_token": "<token>", "expires_in": <seconds>, "authorization": { "bunker_url": "…" } }
```

`expires_in` is the usual session length (`token_expiry_seconds`); `authorization` is present only with a grant.

**The session is a Bearer token the app keeps.** The orders app is on a different site from the customer hostname, so a Keycast cookie would not be sent (Safari blocks it outright). Verify sets no cookie; the app sends `Authorization: Bearer <session_token>` on every call. The token never goes in a URL or a log.

**Not built:** opening the link on a different device from the one that asked.

---

## 4. The `commerce_envelope` permission — #92

An order is a kind `1327` message (the Open Markets private commerce envelope). The app asks Keycast to NIP-44-encrypt it to the merchant and to sign the kind `13` seal around it, and signs the outer kind `1059` gift wrap itself with a throwaway key. Keycast never signs the `1327` message.

| Call | Allowed when |
|---|---|
| Encrypt | To the merchant, and the plaintext is a kind `1327` whose `p` tags include the merchant; or to the customer's own key, with the same check (their copy) |
| Sign | Kind `13` only |
| Decrypt | From any sender (replies arrive in gift wraps from throwaway keys) |

Everything else is refused. Code: `core/src/custom_permissions/commerce_envelope.rs`; config `{ "merchant_pubkey": "<hex>" }`.

**One policy row per merchant**, named `commerce_envelope:<merchant hex>`, created on first use by `PolicyRepository::find_or_create_commerce_envelope`. (Policy slugs are unique and 50 characters wide, so the merchant cannot live only in the permission config.)

The permission is listed in `web/src/lib/types.ts`, but the web form has no merchant field, so choosing it there makes a permission that refuses everything. `DISABLE_WEB_UI` is on for Synvya, so nobody reaches that form.

---

## 5. Encrypt and decrypt are checked on the relay path — #91

The NIP-46 relay path (`signer/src/signer_daemon.rs`) now checks the policy for `nip44_encrypt`, `nip44_decrypt`, `nip04_encrypt` and `nip04_decrypt`, as the HTTP paths already did.

- The default `All Access` policy uses `allowed_kinds`, which allows encrypt and decrypt, so authorizations on it, including Synvya Server's restaurant authorizations, are unaffected. An authorization on a custom policy that limits encryption is now limited.
- A refused relay request gets no response, as a refused signature already did, so the client waits until it times out. Sending an error back would be better; not done.

---

## 6. Tenant isolation — #93

- Every path passes the request's tenant to `validate_ucan_token`, and a session with no tenant is refused. An owner session is refused on the customer hostname and the reverse, by Bearer or cookie.
- `/api/nostr`'s handler cache includes the tenant in its key, and the tenant cache checks the allowlist first.
- `ALLOWED_TENANT_DOMAINS` is required in `docker-compose.synvya.yml`. Any other `Host` gets 400, including tenants already in the database. **Any service calling Keycast on another hostname is refused**; confirm Synvya Server's `KEYCAST_URL` is `auth.synvya.com` / `auth.staging.synvya.com`.
- **The customer hostname serves only customer routes.** `customer_tenant_guard` (`api/src/api/tenant.rs`) returns 404 for every `/api` route not in `is_customer_route`: `/nostr`, `/auth/magic-link`, `/auth/magic-link/verify`, `/customer/account`, `/customer/authorizations`, `/customer/authorizations/revoke`. Without it a customer session could, for example, call `/user/bunker/create` with `policy_slug: "full"` and undo the commerce permission, or use the password routes. **A new customer route must be added to `is_customer_route`.**

### 6.1 `/api/nostr` checks the authorization's owner — #101

`/api/nostr` refuses a token naming an authorization that belongs to another user, with the usual invalid-token error, and does not cache it.

---

## 7. Revocation takes effect at once — #94

Both lookups (`find_policy_id_by_origin`, `find_latest_bunker_pubkey`) skip revoked rows, and revoking removes the authorization's entry from the HTTP handler cache, so a revoked app fails on its next `/api/nostr` call.

The cache is per process. Synvya runs one container, so removal reaches every instance; a deployment with several instances would keep serving a revoked authorization from the others until their entries expire.

---

## 8. Rate limits — #95

Per-IP and per-email limits (`api/src/rate_limit.rs`) on the six endpoints that send email or call KMS: `/api/auth/register`, `/api/headless/register`, `/api/oauth/register`, `/api/auth/forgot-password`, `/api/auth/resend-verification`, team invitations, plus `/api/auth/magic-link` (§3.2). Limits above one per window use `incr_with_ttl`. The IP default is 60 per hour (`RATE_LIMIT_IP_PER_HOUR`), because these endpoints also serve owners and CI. The firewall rules stay.

---

## 9. Customer deletion — #96

1. The signed-in customer asks for a deletion link: `POST /api/auth/magic-link` with `"purpose": "delete_account"` and their session. The link goes only to their own email.
2. Verifying that link gives a session that lasts 10 minutes and is the only kind allowed to delete. A stolen ordinary session cannot delete.
3. `DELETE /api/customer/account` with that session (public CORS, on the customer hostname) deletes the account and its key and revokes every authorization. Unused links stop working.
4. Keycast records a notice in `customer_deletion_notices` and POSTs `{ "pubkey", "deleted_at" }` to `SYNVYA_SERVER_DELETION_URL`, signed with NIP-98 using `SERVER_NSEC`, retrying until acknowledged. Delivery is **at least once**: Synvya Server must treat a repeat as harmless. While the URL is unset, notices wait in the table and **subscriptions are not cancelled**.

Restaurant-owner deletion (`/user/account`) is unchanged. Customers do not use it because it is on credentialed CORS, which merchant origins are not on.

---

## 10. Merchants: the approved list — #97, #102

Each merchant's orders app is its own origin with its own authorization on the customer's key. The same email at two merchants is one user, one key, two authorizations.

**The list** — `customer_app_origins`, read at request time, so adding a merchant needs no deploy:

```sql
CREATE TABLE customer_app_origins (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      BIGINT NOT NULL,
    origin         TEXT NOT NULL,         -- https://orders.example.com, no path
    merchant_name  TEXT NOT NULL,         -- shown to customers: "Sign in to Example Coffee"
    merchant_pubkey CHAR(64) NOT NULL,    -- #102: the merchant this app sells for
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, origin)
);
```

**Admin routes**, on the owner hostname with a full admin session (the customer hostname has no admin routes):

| Route | Does |
|---|---|
| `GET /api/admin/customer-origins` | List the approved orders apps |
| `POST /api/admin/customer-origins` | Add one: `{ "origin", "merchant_name", "merchant_pubkey" }`. `origin` is https with no path |
| `DELETE /api/admin/customer-origins` | Remove one: `{ "origin" }`. New sign-ins stop; existing authorizations keep working until revoked |

**Account page routes**, on the customer hostname with the customer's session:

| Route | Does |
|---|---|
| `GET /api/customer/authorizations` | The apps that can act for the customer: origin, merchant name, when granted |
| `POST /api/customer/authorizations/revoke` | Revoke one; it stops at its next call (§7) |

**Binding each app to its merchant — #102.** `merchant_pubkey` is required when an origin is added (hex or npub, stored as hex). At verify (§3.3), Keycast takes the merchant from the row for the link's `app_origin`, which it recorded when the link was requested, so the app cannot change it:
- a `merchant_pubkey` in the request that differs from the row's is refused with 400 and nothing is granted; for a new customer, no account is created either;
- an omitted `merchant_pubkey` uses the row's;
- a `redirect_uri` on another origin than the link's is refused;
- **a refused grant uses up the link.** Keycast learns the link's origin only by consuming it, so a misconfigured app makes the customer ask for a new link;
- a merchant removed from the list after the link was sent: the grant is refused, because there is no merchant left to bind it to;
- **posting an origin again** changes its name and key for new sign-ins only. Customers already signed in keep the merchant they were granted until they are revoked, so correcting a wrong key does not fix existing grants: revoke them as well.

Without this, a compromised orders app could ask for a different merchant and the customer's key would be allowed to send orders there.

**CORS.** Every customer route uses public CORS, which never carries credentials, so CORS needed no per-merchant list. `http://localhost` origins are trusted only with `ALLOW_LOCALHOST_ORIGINS=true` (staging yes, production no).

---

## 11. Fewer KMS calls — #98

`CachingKeyManager` (`core/src/encryption/caching_key_manager.rs`) serves repeat decrypts from a bounded in-memory cache for up to 15 minutes after use. Failures are not cached. Envelope encryption was not chosen, because it would change how every key is stored and need a migration of live keys.

Measured by `api/tests/kms_usage_test.rs`, 100 sign-ins then 100 signatures, all within 15 minutes:

| (encrypt, decrypt) calls | Before | After |
|---|---|---|
| 100 new customers | 100, 200 | 100, 0 |
| 1 returning customer | 1, 200 | 1, 0 |

A visit after the 15 minutes costs one decrypt.

---

## 12. Tests and checks

**`cd api && cargo test` is not enough**: it skips the database tests, which are behind a feature flag. Run what CI runs:

```bash
cargo test --workspace
cargo test -p keycast_core   --features integration-tests --lib
cargo test -p keycast_api    --features integration-tests --lib --tests
cargo test -p keycast_signer --features integration-tests --lib --tests
cargo test -p cluster-hashring --lib -- --ignored
cargo clippy --workspace --all-targets --all-features -- -D warnings -A deprecated
cargo fmt --all -- --check
```

New test files: `bcrypt_cleanup_test`, `tenant_isolation_test`, `magic_link_test`, `magic_link_verify_test`, `revocation_test`, `rate_limit_test`, `customer_deletion_test`, `customer_merchants_test`, `kms_usage_test` (in `api/tests/`), and the relay-path tests in `signer/tests/permission_validation_tests.rs`.

**Checks before production**, on staging after #100 merges:
- restaurant owners register, sign in, manage teams and delete their account as today;
- Synvya Server's takeout and bookings work end to end (§5) — **not run locally**, because the server's local setup drives live tables;
- a customer signs in by email link on a test merchant origin, places an order through the commerce permission, is refused anything else, and deletes their account;
- an owner session is refused on the customer hostname and the reverse;
- a real email arrives through SES, and a real orders app in a browser can call the customer routes (CORS was exercised by script only).

---

## 13. Edge cases

| Case | Behaviour |
|---|---|
| Link clicked twice, or after 15 minutes | 400; the app offers "send a new link" |
| Two links requested, older one clicked | Works if unexpired and unused |
| Email has a restaurant-owner account | Different tenant; a new customer account is created |
| `local_key` sent for an existing account | Ignored |
| Invalid `local_key` | 400; no account created |
| Email scanner opens the link | GET on the app page; nothing consumed |
| Sign-in from an app not on the list | 400; no email |
| Merchant removed from the list | New sign-ins refused; existing customers keep working until revoked |
| Merchant removed after the link was sent | Grant refused; the link is used up |
| App names a different merchant than its row | 400; nothing granted, no account created; the link is used up |
| App omits `merchant_pubkey` | The row's merchant is used |
| Origin posted again with a corrected key | New sign-ins use the new key; existing grants keep the old one until revoked |
| Deletion while Synvya Server's URL is unset | Account deleted; notice waits; subscriptions not cancelled until delivered |

---

## 14. Turning it on

**Once per environment — the customer hostname** (`b2b-auth.staging.synvya.com`, then `b2b-auth.synvya.com`):
1. In Route 53, add an `A` alias record for the hostname pointing at that environment's Keycast load balancer, the same as `auth.*`. Nothing else is needed to route it: the wildcard certificate covers the name, and the HTTPS listener forwards every hostname to Keycast, which refuses any not in `ALLOWED_TENANT_DOMAINS`.
2. Set `CUSTOMER_TENANT_DOMAIN` for that environment in `scripts/load-secrets.sh` and merge it. The merge deploys, and Keycast creates the customer tenant at startup.
3. Give the hostname to the orders app; it sends its Keycast calls there.
4. Once Synvya Server has the deletion endpoint (§9), set `SYNVYA_SERVER_DELETION_URL`. The deploy does not write it yet, so it has to be added to `scripts/load-secrets.sh`.

**Before turning it on in production — the WAF.** Staging and production have different rules (`ec2-deployment.md` §10), and these are made by hand in the AWS console, on `synvya-production-keycast-waf`:
1. Add a rate-based rule for `/api/auth/magic-link`, which sends email like the routes that already have one. Check that their 10 requests per minute per IP suits it: customers behind one shared network count as one IP.
2. Add `AWSManagedRulesAmazonIpReputationList`.
3. Decide on `AWSManagedRulesCommonRuleSet` and `AWSManagedRulesKnownBadInputsRuleSet`, which staging has. Check real order sizes first: the common rules block request bodies over 8 KB, and orders are encrypted through `/api/nostr`.

**Once per merchant — the approved list:** `POST /api/admin/customer-origins` on the owner hostname with `{ "origin": "https://orders.example.com", "merchant_name": "Example Coffee", "merchant_pubkey": "<hex or npub>" }`. `merchant_pubkey` is required, and a missing or invalid one gets 400. Check it: customers signing in through that app can only send orders to this key. It works at once, with no deploy, and fails until the customer hostname is set. There is no screen for it yet. A merchant not on the list gets 400 on sign-in requests and no email is sent. Posting the same origin again changes its name and key for new sign-ins; customers already signed in keep the merchant they were granted until revoked.
