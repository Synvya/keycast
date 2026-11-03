# Customer Accounts

Spec for passwordless customer accounts in Keycast: sign-in by email link, a commerce permission that lets an orders app place orders for a customer with one merchant and nothing else, and the fixes Keycast needs before it holds customer keys.

**Issues:** milestone [Orders: customer accounts](https://github.com/Synvya/keycast/milestone/3) — #88 to #98. Each section below names its issue.

**System context:**
- [Cross-repo: Customer Accounts](https://github.com/Synvya/docs/blob/main/02-auth-and-identity/architecture/customer-accounts.md) — who does what across the orders app, Keycast and Synvya Server, and the sign-in sequence.
- [Orders PRD](https://github.com/Synvya/docs/blob/main/06-domains-and-services/specs/prd-orders.md) §8 and §13 — the product requirements (`[OR-8]`, `[OR-19]` – `[OR-22]`).
- [Order of work](https://github.com/Synvya/docs/blob/main/02-auth-and-identity/internal/todo-keycast-customer-accounts.md) — stages, priorities and gates.
- [team-invite-by-email.md](team-invite-by-email.md) — the closest earlier email-token feature; follow its patterns.

**Verified against:** `synvya-staging` at `5cb67b0` (2026-10-21). Line numbers below are from that commit and drift; find code by the function name.

---

## 0. Branch and PR: one branch, one PR

All of this work is on the `alejandro-dev` branch of `Synvya/keycast`, and it ships as **one PR**: [#100](https://github.com/Synvya/keycast/pull/100), `alejandro-dev` → `synvya-staging`. Keycast takes a long time to roll out, so the issues are not shipped one at a time.

- Bring `alejandro-dev` up to date with `synvya-staging` before starting. Do not create other branches.
- Work the issues in the order of §12. Make at least one commit per issue, with `Fixes #<n>` in the message, so each issue closes when #100 merges and each change can be reviewed on its own.
- Push to `alejandro-dev` as you go; every push updates #100. Do not open another PR.
- #100 merges once, when every issue is done and the local checks in §12 pass. That deploys to staging; the staging checks in §12 run there, and production follows by merging `synvya-staging` into `synvya`, as usual.
- Nothing goes upstream. [SYNVYA.md](../../SYNVYA.md) rule 2 sends work that could be contributed (the email-link login looks like it) to `main` and `divinevideo/keycast`; Synvya decided not to contribute this work.

**Generic by design.** This is for any merchant that sells through Synvya's orders app, not one customer. No merchant's name, domain or prices belong in code, config defaults or tests; examples use `orders.example.com`.

---

## 1. Scope

**What Keycast owns (new):**
- Passwordless accounts in a separate customer tenant.
- Sign-in links: creation, email delivery, single-use verification.
- The `commerce_envelope` permission.
- Telling Synvya Server when a customer account is deleted.

**What Keycast does not own:**
- The sign-in, landing and account pages. Those are in the orders app at `orders.<merchant-domain>`.
- Orders, subscriptions, cards. Synvya Server owns them and never holds access to a customer's key.

---

## 2. Stop the cleanup job deleting passwordless accounts — #88

**Do this first.** Nothing below can be tested until it is fixed.

`spawn_cleanup_task` in `api/src/bcrypt_queue.rs` (started from `keycast/src/main.rs`) runs every 5 minutes:

```sql
DELETE FROM users WHERE password_hash IS NULL
  AND vine_id IS NULL
  AND email IS NOT NULL
  AND created_at < NOW() - INTERVAL '10 minutes'
```

It exists because `register` inserts the user with `password_hash` NULL and hashes the password later on the bcrypt queue; a row whose hash never arrives is an abandoned sign-up. A customer account has an email and never a password, so this deletes every one of them, with its key.

**Fix.** Password sign-ups always store an `email_verification_token` when the row is created; email-link accounts never set that column (their tokens live in `magic_link_tokens`, §3). Add the condition:

```sql
  AND email_verification_token IS NOT NULL
```

Before relying on it, confirm every insert path that leaves `password_hash` NULL also sets `email_verification_token` (`register` in `api/src/api/http/auth.rs` and the `UserRepository` create functions in `core/src/repositories/user.rs`). If one does not, use an explicit marker instead: a `password_pending boolean` set by the register path and cleared by the bcrypt worker, and delete only rows where it is true.

**Tests** — extend `api/tests/bcrypt_cleanup_test.rs`, which already has `test_cleanup_deletes_stale_signups`, `test_cleanup_preserves_recent_signups` and `test_cleanup_does_not_delete_preloaded_users`:
- `test_cleanup_preserves_passwordless_accounts`: a user with an email, no password, no verification token, created 15 minutes ago, survives a run, and so does its `personal_keys` row.
- The existing stale-signup test still deletes its row.

---

## 3. Email-link sign-in

### 3.1 Data model

New migration in `database/migrations/` (follow the `YYYYMMDDHHMMSS_name.sql` naming):

```sql
CREATE TABLE magic_link_tokens (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     BIGINT NOT NULL,
    email         VARCHAR(255) NOT NULL,      -- normalized: trim + lowercase
    token_hash    CHAR(64) NOT NULL UNIQUE,   -- sha256 of the token, hex
    purpose       VARCHAR(20) NOT NULL DEFAULT 'sign_in',
    app_origin    TEXT NOT NULL,              -- the page the link lands on
    expires_at    TIMESTAMPTZ NOT NULL,       -- created_at + 15 minutes
    consumed_at   TIMESTAMPTZ,
    request_ip    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_magic_link_purpose CHECK (purpose IN ('sign_in', 'delete_account'))
);
CREATE INDEX idx_magic_link_tokens_email ON magic_link_tokens (tenant_id, email, created_at);
```

- Token: 32 random bytes, hex. Use `generate_secure_token` (already used for verification and reset tokens).
- **Store only the hash.** Unlike `users.email_verification_token` and `password_reset_token`, the plain token is never written to the database.
- No `user_pubkey` column: the account may not exist until the link is clicked.
- Purge rows older than a day on the existing cleanup schedule.

Repository: `core/src/repositories/magic_link_token.rs` with `create`, `consume` (one `UPDATE … SET consumed_at = NOW() WHERE token_hash = $1 AND tenant_id = $2 AND consumed_at IS NULL AND expires_at > NOW() RETURNING …`, so a token can be consumed once even under concurrent clicks), `count_recent(email, since)` and `purge_expired`.

### 3.2 `POST /api/auth/magic-link` — request a link — #89

**Request**
```json
{ "email": "dana@example.com", "app_url": "https://orders.example.com/signin" }
```

**Behaviour**
1. Normalize `email` (`trim().to_lowercase()`). Reject a malformed address with 400.
2. Check `app_url` with `app_url_is_allowed` (`api/src/api/http/auth.rs`, matches entries in `ALLOWED_ORIGINS`). Reject with 400 if not allowed.
3. Throttle with Redis `set_nx_ex` (`api/src/redis.rs`): at most one link per email per 60 seconds, at most 5 per email per hour (`count_recent`), and a per-IP limit (suggest 20 per hour). When throttled, **still answer 200 with `{ "success": true }`** and send nothing; log it.
4. Create the token row (purpose `sign_in`) and send the email in a spawned task, so response time does not reveal whether an email was sent.
5. **Do not create a user or a key here.** That happens on verify (§3.3).

**Response** — always, for known and unknown emails alike:
```json
{ "success": true }
```

**Email.** Add `send_magic_link_email(to, link, merchant_name)` to the `EmailSender` trait in `api/src/email_service.rs`, with implementations for `DevEmailSender`, `SendGridEmailSender` and `SesEmailSender`, following `send_team_invite_email`. The link is `app_url` with `?token=<token>` appended. Subject "Sign in to <merchant>"; one button; "This link works once and expires in 15 minutes." The email never mentions Keycast, Synvya, keys or Nostr. Use the configured sender; per-merchant sender and branding is an open product decision.

**Route.** Public, no session needed. Add it beside `email_routes` in `api/src/api/http/routes.rs` on `public_cors`.

### 3.3 `POST /api/auth/magic-link/verify` — sign in — #90

The orders app's landing page reads `token` from its URL and posts it. **POST only**: email scanners open links with GET, and a GET must never consume a token.

**Request**
```json
{
  "token": "…",
  "client_id": "orders.example.com",
  "redirect_uri": "https://orders.example.com/signin",
  "scope": "policy:commerce_envelope",
  "merchant_pubkey": "<hex>",
  "local_key": "<hex secret key, optional>"
}
```

`client_id`, `redirect_uri`, `scope` and `merchant_pubkey` are optional as a group: without them the call only signs the customer in.

**Behaviour**
1. `consume` the token for the request's tenant. Unknown, used, expired or other-tenant tokens all fail with the same 400 `invalid_or_expired_link`.
2. Look up the user by tenant and email.
   - **No user:** create the user (`email_verified = true`, no password, no verification token) and a key. If `local_key` was sent and is a valid secret key, store that key (KMS-encrypted, as `personal_keys` are today) instead of generating one. Lift the create logic from `register_with_personal_key` (`core/src/repositories/user.rs`) into a `find_or_create_passwordless` that does not set a password.
   - **User exists:** sign in with the existing key. **Never replace an existing key**, even when `local_key` is sent; ignore it.
3. Mint the session with `generate_server_signed_ucan` (`api/src/api/http/auth.rs`), so sign-in needs no KMS decrypt of the customer's key. Pass `tenant_id` (required, see §6) and `is_first_party = false`. For purpose `delete_account` tokens see §9.
4. When `client_id`, `redirect_uri`, `scope` and `merchant_pubkey` are present, create the app's authorization with the `commerce_envelope` permission for that merchant (§4), reusing `create_oauth_authorization_and_token` (`api/src/api/http/oauth.rs`). One click then gives the app a session and an authorization ready to sign.
5. Never include the pubkey, npub or any key material in the response.

**Response**
```json
{ "success": true, "session_token": "<ucan>", "expires_in": <seconds>, "authorization": { "bunker_url": "…" } }
```

`expires_in` is the same session length Keycast uses today (`token_expiry_seconds`).

**How the app holds the session — decision needed.** Keycast's session cookie is `SameSite=Lax` (`format_session_cookie`). The orders app (`orders.<merchant-domain>`) and the customer tenant's hostname are different sites, so a browser will not send that cookie on the app's background calls, and Safari blocks it as a third-party cookie. The route also sits on `public_cors` today for exactly this reason ("same-origin sets cookie, cross-origin uses Bearer"). This spec therefore returns the session as `session_token` in the body and the app sends it as `Authorization: Bearer`. The alternative is to proxy the customer tenant under each merchant's hostname (for example `orders.<merchant-domain>/id/*`), which makes the cookie first-party. Confirm the choice before building #90.

**Route.** If the session is returned in the body, put the route on `public_cors` like `verify_email`. If the proxy route is chosen, put it on `auth_cors` and set the cookie with `format_session_cookie`.

**Not in this issue.** Opening the link on a different device from the one that asked. Keycast's device-code polling (`oauth_poll:*` in Redis) could do this later.

---

## 4. The `commerce_envelope` permission — #92

How an order is sent: the app builds a kind `1327` message (the Open Markets private commerce envelope), asks Keycast to NIP-44-encrypt it to the merchant and to sign the kind `13` seal around it, and signs the outer kind `1059` gift wrap itself with a throwaway key. **Keycast never signs the `1327` message.** It also encrypts the same message to the customer's own key for their copy.

**Config** (stored in the permission's JSON like the other types):
```json
{ "merchant_pubkey": "<hex>" }
```

**Rules**

| Call | Allowed when |
|---|---|
| `can_encrypt(plaintext, sender, recipient)` | `recipient == merchant_pubkey` **and** `plaintext` parses as an unsigned event of kind `1327` whose `p` tags include `merchant_pubkey` — or `recipient == sender` (the customer's own copy), with the same parse check |
| `can_sign(event)` | `event.kind == 13` |
| `can_decrypt(ciphertext, sender, recipient)` | Always (replies come in gift wraps from throwaway keys, the same reason `decrypt_only` allows any sender) |

Everything else is refused: another recipient, a non-`1327` plaintext, a `1327` naming another merchant, signing any other kind.

**Where.** `core/src/custom_permissions/commerce_envelope.rs` implementing `CustomPermission` (`core/src/traits.rs`). Register it in `core/src/custom_permissions/mod.rs` (`AVAILABLE_PERMISSIONS`), in the match in `core/src/types/permission.rs`, and in `web/src/lib/types.ts`. Follow `encrypt_to_self.rs` and `decrypt_only.rs`.

**Tests** — unit tests in the module for each allowed case and each refusal above.

**Depends on #91.** Without it, encrypt and decrypt rules are not checked on the relay path at all.

---

## 5. Check encrypt and decrypt permissions on the relay path — #91

In `signer/src/signer_daemon.rs`, the NIP-46 `sign_event` branch (around line 1318) checks the policy through `validate_permissions_for_sign` (around line 126). The `nip44_encrypt`, `nip44_decrypt`, `nip04_encrypt` and `nip04_decrypt` branches (around lines 1345–1476) do the crypto without any check. The HTTP paths do check: `api/src/handlers/http_rpc_handler.rs` around lines 146 and 168, and `api/src/api/http/auth.rs` around lines 2621 and 2702.

**Fix.** Add `validate_permissions_for_encrypt(plaintext, recipient)` and `validate_permissions_for_decrypt(ciphertext, sender)` beside `validate_permissions_for_sign`, loading permissions the same way (OAuth or team authorization, AND logic, empty list allows all), and call them in the four branches. Refuse with the same error shape as a refused signature.

**Before merging.** Synvya Server signs and encrypts takeout and bookings messages for restaurants over this path. Check the policies on the server's restaurant authorizations allow the encrypt and decrypt calls it makes, or takeout and bookings break the moment this ships. Run takeout and a booking end to end on staging after deploying.

**Tests.** Add to `api/tests/rpc_permission_edge_cases_test.rs` or a signer test: an `encrypt_to_self` policy refuses an encrypt to another pubkey over the relay path; a `full_access` policy still allows it.

---

## 6. Tenant isolation and the customer tenant — #93

What the code does today (corrects the earlier review, which said the tenant was never checked):

- `validate_ucan_token(auth, expected_tenant_id)` (`api/src/ucan_auth/validation.rs`) checks the session's `tenant_id` fact **only when `expected_tenant_id != 0`**, and when the fact is missing it only logs a warning and allows the request.
- The main session extractor passes `0`: `api/src/api/extractors.rs` (around lines 64 and 93). So does `/api/nostr` (`api/src/api/http/nostr_rpc.rs`, around line 461) and one call in `auth.rs` (around line 458). Those paths never check the tenant. The OAuth paths and account deletion do pass the tenant.
- `TenantExtractor` (`api/src/api/tenant.rs`) creates a tenant for any `Host` unless `ALLOWED_TENANT_DOMAINS` is set, and it is not set in `docker-compose.synvya.yml` or the Synvya secrets.
- `PersonalKeysRepository::find_encrypted_key` (`core/src/repositories/personal_keys.rs`) looks up by pubkey with no tenant; `find_encrypted_key_for_tenant` and `find_encrypted_key_by_tenant` exist beside it.

**Fix**
1. Pass the request's tenant to `validate_ucan_token` from the extractors and `nostr_rpc.rs`.
2. Refuse a session with no `tenant_id` fact when a tenant is expected (turn the warning into an error). Check that every session Keycast mints carries the fact; `generate_server_signed_ucan` and `generate_ucan_token` both take `tenant_id`.
3. Set `ALLOWED_TENANT_DOMAINS` on staging and production.
4. Replace calls to `find_encrypted_key` with the tenant-scoped versions.
5. Create the customer tenant for its hostname (hostname still to be chosen).

**Tests.** Extend `api/tests/tenant_race_condition_test.rs` or add one: a restaurant-owner session is refused on the customer hostname and the reverse; a request with an unknown `Host` gets no tenant.

---

## 7. Revocation takes effect at once — #94

- `find_policy_id_by_origin` and `find_latest_bunker_pubkey` (`core/src/repositories/oauth_authorization.rs`, around lines 295 and 341) do not filter `revoked_at IS NULL`; `has_active_for_origin` beside them does. Add the filter.
- The HTTP handler cache (`new_http_handler_cache` in `api/src/handlers/http_rpc_handler.rs`, one-hour idle) is never cleared on revoke; `/api/nostr` (`api/src/api/http/nostr_rpc.rs`) keeps serving the cached handler. Where a revoke sends `AuthorizationCommand::Remove` to the signer (`api/src/api/http/admin.rs`, `auth.rs`), also remove the entry from `http_handler_cache`.

**Test.** Revoke an authorization; the app's next `/api/nostr` call fails. Related: #55 (team member removal should revoke).

---

## 8. Rate limits inside the app — #95

These send an email or make a KMS call on every request, with no in-app limit: `/api/auth/register` (also a KMS encrypt before verification), `/api/headless/register`, `/api/oauth/register`, `/api/auth/forgot-password`, `/api/auth/resend-verification`, team invitations, and the new `/api/auth/magic-link`. The firewall limits three paths at 10 per minute per IP, set by hand.

Add per-IP and per-email limits with `set_nx_ex`, in one small helper reused by every handler. Keep the firewall rules.

---

## 9. Customer account deletion — #96

`delete_account` (`api/src/api/http/auth.rs`, around line 3204) already deletes an account: it accepts the session cookie or Bearer, requires a user-signed session or a `first_party` fact, and `UserRepository::delete_account` removes team memberships, codes and the user, and tells the signer to drop the user's bunkers.

**Gap 1 — customer sessions cannot delete.** Email-link sessions are server-signed with `first_party = false` (§3.3). Add the `delete_account` purpose: the account page asks for a deletion link (`POST /api/auth/magic-link` with `"purpose": "delete_account"`, for a signed-in customer only); verifying that token mints a session with `first_party = true` that expires in 10 minutes. Only that session can delete. A stolen ordinary session cannot.

**Gap 2 — Synvya Server is not told.** After a successful deletion of a customer-tenant account, POST the deleted pubkey to a Synvya Server endpoint so it cancels subscriptions and removes the saved card. Sign the call with NIP-98 using Keycast's server key, the reverse of [keycast-service-auth.md](keycast-service-auth.md). Retry until acknowledged. Agree the endpoint with the server work; until it exists, record pending notices in a table.

Restaurant-owner deletion behaves exactly as today.

---

## 10. One account across merchants — #97

Each merchant's orders app is its own origin (`orders.<merchant-domain>`) with its own authorization on the customer's key. The same email at two merchants is one user and one key.

- Allowed app origins come from the `ALLOWED_ORIGINS` environment variable (`app_url_is_allowed`) and CORS from `origin_is_allowed` (`keycast/src/main.rs`). Adding a merchant should not need a redeploy: move the customer tenant's allowed origins to a table (or the tenant's settings) read at request time.
- `origin_is_allowed` always allows `http://localhost*`, also in production. Allow it only when an explicit dev flag is set.
- `forgot_password_url_for_auth_host` in `api/src/api/http/oauth.rs` hardcodes `account.synvya.com`; leave it for owners, but make sure no customer flow reaches it.
- Account page API: list the customer's authorizations (app origin, granted date) and revoke one.

---

## 11. Fewer KMS calls — #98

Keycast decrypts a key through KMS on every password login (to self-sign the session), on every cold signing handler, and on the `/api/user/sign` slow path. `AwsKeyManager` (`core/src/encryption/aws_key_manager.rs`) calls Encrypt and Decrypt directly with no cached data key. Email-link sessions are server-signed, which removes the login decrypt for customers. Measure the rest before changing: count KMS calls for 100 sign-ins followed by 100 signatures, then use envelope encryption with a cached data key or a bounded per-session cache.

---

## 12. Order of work and the one rollout

All of it is in PR #100. The order is the order of commits on `alejandro-dev`:

| Order | Issue | Why here |
|---|---|---|
| 1 | #88 cleanup job | Every later test creates a passwordless account |
| 2 | #93 tenant isolation, customer tenant | Changes the session checks everything else relies on |
| 3 | #91 relay-path checks | Before #92 means anything |
| 4 | #92 commerce permission | Granted by #90 |
| 5 | #89 request a link | |
| 6 | #90 verify and sign in | Needs the session decision in §3.3; if it is still open, do the rest first |
| 7 | #94 revocation, #95 rate limits | Small, independent |
| 8 | #96 deletion, #97 across merchants | Build on #90 |
| 9 | #98 fewer KMS calls | Measure first; record the numbers in the PR |

**Before #100 merges**, run `cd api && cargo test` and the flows below on a local stack. **After it merges** (staging deploys from `synvya-staging`), run the same flows on staging before promoting to production:
- restaurant owners still register, sign in, manage teams and delete their account as today;
- Synvya Server's takeout and bookings still work end to end (the #91 risk, §5);
- a customer signs in by email link on a test merchant origin, places an order through the commerce permission, is refused anything else, and deletes their account;
- a restaurant-owner session is refused on the customer hostname (#93).

## 13. Edge cases

| Case | Behaviour |
|---|---|
| Link clicked twice | Second click fails with `invalid_or_expired_link`; the app offers "send a new link" |
| Link clicked after 15 minutes | Same |
| Two links requested, older one clicked | Works if unexpired and unused; each token is independent |
| Email has a restaurant-owner account | Different tenant; the customer tenant has no such user, so a new customer account is created |
| `local_key` sent for an email that has an account | Ignored; the existing key is used |
| Invalid `local_key` | 400; no account created |
| Email scanner opens the link | GET on the app page; nothing consumed until the page posts |
