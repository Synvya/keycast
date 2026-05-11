# Admin User Provisioning

Keycast-vantage-point reference for the cross-repo "admin user provisioning" feature. **No Keycast code changes are required for this feature.** This file documents which existing Keycast endpoints are consumed by the Synvya server during admin onboarding, so future Keycast maintainers don't inadvertently break a downstream contract.

The same feature has parallel specs in the other repos:

- [Cross-system `admin-user-provisioning.md`](https://github.com/Synvya/docs/blob/main/architecture/admin-user-provisioning.md) — system-wide design and the two-path UX.
- [Server `admin-user-provisioning.md`](https://github.com/Synvya/server/blob/staging/docs/specs/admin-user-provisioning.md) — TypeScript implementation.
- [Systemtools `admin-user-provisioning.md`](https://github.com/Synvya/systemtools/blob/staging/docs/specs/admin-user-provisioning.md) — UI: segmented "Add Admin" control.

**System context** (Keycast):

- [Keycast Service Auth](keycast-service-auth.md) — foundation; admin provisioning calls go over this NIP-98 service auth path.
- [Architecture Context](architecture-context.md)
- [Support Users](support-users.md) — sister consumer of the same foundation.

---

## 1. Endpoints Consumed

The Synvya server, signing each call with `SERVER_BUNKER_CLIENT_PRIVATE_KEY` per the [Keycast Service Auth](keycast-service-auth.md) foundation, calls these existing Keycast endpoints during admin provisioning:

| Endpoint | File | Purpose in this flow |
|---|---|---|
| `GET /api/admin/user-lookup?q=<email>` | [`api/src/api/http/admin.rs:844`](../../api/src/api/http/admin.rs) | Detect if a Keycast account already exists for the recipient's email. If yes, skip preload + claim. |
| `POST /api/admin/preload-user` | [`api/src/api/http/admin.rs:208`](../../api/src/api/http/admin.rs) | Generate a fresh Keycast account; Keycast generates the keypair, encrypts the nsec, returns the pubkey. |
| `POST /api/admin/claim-tokens/batch` | [`api/src/api/http/admin.rs:590`](../../api/src/api/http/admin.rs) | Called with a single-item `vine_ids` array and `delivery_email` set to the new admin's address. Generates the claim token **and sends the claim email via Keycast's existing `send_claim_email` path** (SES, `synvya.com` domain). |
| `GET /api/claim?token=...` | [`api/src/api/http/claim.rs:42`](../../api/src/api/http/claim.rs) | Server-rendered HTML form where the recipient sets email + password. Public route, token-gated. |

The first three are gated by `is_full_admin`. The Synvya server pubkey is recognized as full admin via `ALLOWED_PUBKEYS` per the foundation spec.

The fourth, `/api/claim`, is server-rendered HTML in Rust — **not** part of the SvelteKit web UI. It remains accessible when `DISABLE_WEB_UI=true` because the no-web-UI guard whitelists `/api/*`.

The single-token endpoint `POST /api/admin/claim-tokens` is **not** consumed by this flow. The reason: it doesn't accept `delivery_email`, and we need Keycast to send the email (the Synvya server has no email infrastructure of its own). The batch endpoint already supports `delivery_email` and works correctly with a one-item array — calling it that way is the path of least resistance and requires zero Keycast change.

## 2. Vine-Flavored Field Repurposing

`POST /api/admin/preload-user` requires `vine_id` and `username`. These are Vine-import vocabulary; admin provisioning has no Vine semantics. The Synvya server synthesizes both:

- `vine_id`: `"synvya-admin-${uuid}"` — guaranteed unique per call. Internally Keycast uses this as the lookup key for the claim flow.
- `username`: derived from email local-part, with numeric suffix on conflict.

This is a small semantic wart — a non-Vine flow flowing through Vine-named fields. It is acknowledged and accepted; **no Keycast change is requested as part of this spec**. A future cleanup PR could rename the field (e.g. `preload_id`) with a backwards-compatible alias, but it is not blocking.

## 3. What Must Not Break

If you are refactoring or simplifying these endpoints, please preserve:

- The `vine_id` field on `preload-user` (or provide an alias). The Synvya server keys its preload + claim sequence on whatever value is sent in this field.
- The `delivery_email` field on `claim-tokens/batch` and the email-send branch at [`admin.rs:730`](../../api/src/api/http/admin.rs). Synvya admin provisioning depends on this — without it, new non-Nostr-native admins have no path to a Keycast account.
- The behavior that Keycast iterates `vine_ids` and sends one email per token. A single-item array must result in one email; this is the shape Synvya admin provisioning relies on.
- The `email_verified = true` outcome of a successful claim. Synvya admins must be able to log in immediately after claiming, without an additional verify-email round-trip.
- The server-rendered `/api/claim` HTML page surviving with `DISABLE_WEB_UI=true`. Synvya production has no SvelteKit UI; the claim form is the recipient's only path to set a password.

## 4. Side Effects on Keycast

Once admin provisioning ships, expect a steady-state pattern of:

- One `preload-user` + one `claim-tokens/batch` (single-item) call per Synvya admin onboard (Path B; "by email").
- One outbound SES email per onboard (subject "Your Synvya account is ready to claim", from a `synvya.com` address).
- Claim activity on `/api/claim` for those users.
- New `users` and `personal_keys` rows for each claimed admin (same as any other Keycast registration).

Volume is low (a handful of admin onboards per quarter at current Synvya scale).

## 5. Email: Keycast-Side

The Synvya server **does not** have email infrastructure. **Keycast sends the claim email** as part of `claim-tokens/batch` when `delivery_email` is set. The path is the existing `send_claim_email` ([`api/src/email_service.rs:765`](../../api/src/email_service.rs)), which is also used today for Vine-import claim emails.

The email content is generic Synvya branding:

- Subject: `"Your Synvya account is ready to claim"`.
- HTML: shared `basic_email_html` template when no kind-0 metadata is published (which is the case for fresh admin preloads — they have no kind-0 published yet). Generic call-to-action: "Your Synvya account is ready. Click the button below to claim it and set up your login."
- Plain-text fallback with the same wording.
- Link target: `{APP_URL}/api/claim?token={token}` (i.e. Keycast's claim form).

For admin onboarding, this email **does not** say "you've been invited as an admin". The systemtools UI compensates by reminding the inviting superadmin to ping the recipient out-of-band so they're not surprised by the email. See [systemtools spec § After-submit confirmation](https://github.com/Synvya/systemtools/blob/staging/docs/specs/admin-user-provisioning.md). If we observe real confusion in practice, we can add an audience parameter to `send_claim_email` and tailor the template — but that is **future work, not this spec**.

## 6. Open Item

- **Pre-claim demotion / removal.** If a systemtools superadmin removes an admin row before the recipient has claimed their Keycast account, the preloaded account in Keycast is orphaned (still exists, never claimed). Cleanup is out of scope for v1; existing claim-token TTL eventually expires the dangling token, but the user/personal_keys row persists. A future cleanup pass could revoke unclaimed preloaded accounts created by the systemtools service identity. Track if it becomes a real problem.

## 7. Cross-References

- For the systemtools UX, see [Systemtools spec](https://github.com/Synvya/systemtools/blob/staging/docs/specs/admin-user-provisioning.md).
- For the server orchestration, see [Server spec](https://github.com/Synvya/server/blob/staging/docs/specs/admin-user-provisioning.md).
- For the system-wide rationale and the two-path UX, see [System spec](https://github.com/Synvya/docs/blob/main/architecture/admin-user-provisioning.md).
