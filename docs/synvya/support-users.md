# Support Users

Spec for letting Synvya support staff create restaurants on behalf of owners and act as any existing restaurant identity for diagnostic/repair work, all from inside the Synvya Restaurant app (`account.synvya.com`).

**System context**:
- [Architecture Context](architecture-context.md)
- [Keycast Boundary](specs/keycast-boundary.md)
- [Restaurant Team E2E](restaurant-team-e2e.md)
- [Team Invite by Email](team-invite-by-email.md)

---

## 1. Architectural View

### The product problem

Synvya support staff (Maria, et al.) need to onboard restaurants and help fix issues for restaurants that are already onboarded. Today the Restaurant app assumes a 1:1 relationship between a logged-in user and a restaurant: an owner registers, a team is created with the restaurant identity as the team key, the owner is the team's admin. Support staff cannot enter that flow at all — they have no path to (a) provision a restaurant on behalf of an owner who hasn't onboarded yet, or (b) sign as a restaurant they don't own to repair menu data, fix profile fields, etc.

### The architectural choice

Two designs were considered for how the Restaurant app authenticates support actions against Keycast:

1. **Keycast-native** (chosen) — extend Keycast's existing `support_admin` role so support staff can create teams and act as any restaurant team's identity. The Restaurant app talks to Keycast directly, with the support admin's UCAN as authorization. No request-time proxy in `Synvya/server`.

2. **Server-mediated** — add a `support` role to `Synvya/server`'s admin allowlist, have the Restaurant app call new server endpoints, and have the server proxy each support action to Keycast.

Option 1 was chosen because Keycast **already** has a `support_admin` role — Redis-backed, baked into UCANs at login, enforced on 8 existing admin endpoints used by `systemtools` (user lookup, claim tokens, authorization revocation, etc.). The role mechanism, the Redis allowlist, and the audit shape are already in production. Adding two new permission points (team creation + just-in-time team access) inside that existing mechanism is significantly smaller than building a parallel system in `Synvya/server`, and keeps the request-path policy boundary on the resource that owns identity (Keycast).

The `support_admin` role already grants read access to a user's teams and authorizations and the ability to revoke authorizations and issue claim tokens. This spec adds two write-side capabilities: **create new teams** and **just-in-time membership** on existing teams.

### Defining who is a support agent

`systemtools` is the source of truth for who is a Synvya support agent. Keycast's `support_admins` Redis set is a **managed mirror** that the `systemtools` backend keeps in sync — it is never edited by humans directly.

Concretely, `systemtools`' admin user record gains a `support` flag, **orthogonal** to the existing `pulse_only | admin | superadmin` role (a user can have `support: true` independently of any systemtools-UI role). When a `systemtools` `superadmin` toggles the flag on a user, the `systemtools` backend (a) updates its DynamoDB admin table, and (b) calls Keycast `POST /api/admin/support-admins` (or the matching `DELETE` on demotion) to update the Redis mirror. Next time that user logs into Keycast, `is_support_admin()` returns true and the issued UCAN carries `admin_role: "support"`.

For step (b) to authorize against Keycast, the `systemtools` backend signs each call with NIP-98 using a dedicated service identity. Keycast calls pubkeys listed in `ALLOWED_PUBKEYS` **full admins** — operator-level identities with full Keycast authority. The `systemtools` service pubkey is one such full admin, added to the `synvya/{env}/keycast/allowed-pubkeys` secret once at bootstrap. Bootstrap human full admins (Synvya leadership/engineering with direct Keycast authority) are added to the same secret manually and managed by the same secret-update process.

The `systemtools` `superadmin` role does **not** automatically grant Keycast full admin. They are independent: a Synvya leader who needs direct Keycast authority is in `ALLOWED_PUBKEYS` *and* has the systemtools `superadmin` role, by separate operations. This is the deliberate manual-sync boundary.

### What the Restaurant app does after this lands

- A support user logs in to `account.synvya.com` with their normal email/password, no different from a restaurant owner. Keycast issues a UCAN that carries `admin_role: "support"`.
- The app shows a restaurant picker (UI already exists; the `TeamSelector` component is gated on `teams.length > 1`). For owners with one team, this is a no-op.
- For support users only, the picker shows a "Create new restaurant" action and a "Open another restaurant" search action.
- "Create new restaurant" calls Keycast's existing `POST /api/teams` (after the gate change in §3.1). The support user becomes admin of the new team via the existing `create_with_admin` flow and can immediately add the stored key, the authorization, and start populating the restaurant's profile.
- "Open another restaurant" finds a target via the existing `user-lookup` + `user-teams` admin endpoints, then calls the new `POST /api/admin/teams/:id/support-access` to be added as a member with a fresh authorization. The picker switches active restaurant; signing now happens as that restaurant's identity.
- On logout, on switching active restaurant, or on session timeout, the app calls `DELETE /api/admin/teams/:id/support-access` to revoke the authorization and remove the support membership.

### What does not change

- Restaurant owner registration, login, claim flow.
- Existing team admin/member permission model. Owners are still admins of their teams; nothing about that changes.
- The `TeamSelector` UI for owners who happen to belong to more than one team.
- `Synvya/server`'s identity, secrets, and the `SERVER_BUNKER_CLIENT_PRIVATE_KEY` it uses to sign on behalf of restaurants. This spec does not touch the always-on signing path. `Synvya/server` is not in the request path for any support action.
- Existing 8 `is_support_admin` admin endpoints. No regressions.
- The manual sync between Synvya leadership/engineering pubkeys and Keycast's `ALLOWED_PUBKEYS` secret. Full admin status remains a manually-curated bootstrap list; `systemtools` does not manage it.

### Tenant scoping note

The `support_admins` Redis set is tenant-global (single key, not namespaced by tenant). This is consistent with the current implementation. For Synvya's single-tenant production setup that is correct. If Keycast becomes multi-tenant in a Synvya context, support admins should be re-scoped per tenant; this is called out explicitly in §10.

---

## 2. Scope

### What Keycast owns (new)

- `create_team` gate widening to allow `is_support_admin()` callers.
- New endpoints for atomic just-in-time support access on existing teams:
  - `POST /api/admin/teams/:id/support-access` — add the calling support admin as member of the team, mint a fresh `Authorization` against the team's first stored key, return the bunker URL.
  - `DELETE /api/admin/teams/:id/support-access` — revoke the support admin's active authorizations on the team and remove their membership.
- A NIP-98 (kind:27235) service-auth path that resolves a request-bound signed envelope to a full-admin context when the signing pubkey is in `ALLOWED_PUBKEYS`. This is what lets the `systemtools` backend write to `support_admins` without needing a human's session cookie.
- Audit log lines for both new endpoints and the systemtools-mirror operation, mirroring the `revoke_authorization` log pattern.

### What `systemtools` owns (new)

- A `support` flag on the existing admin user record (DynamoDB `synvya-{env}-admin-users`), orthogonal to the existing role enum.
- A "Support" management surface in the `systemtools` UI (visible to `superadmin` only) that toggles the flag on/off for any existing admin user.
- A backend mirror that, on each toggle, also calls Keycast `POST /api/admin/support-admins` (or `DELETE`) signed with NIP-98 by the systemtools service identity.
- A bootstrap configuration: the systemtools service nsec held in AWS Secrets Manager; the corresponding pubkey listed in `synvya/{env}/keycast/allowed-pubkeys`.

### What Keycast does not own

- The Restaurant app's restaurant picker UI, "Create new restaurant" button, and "Open another restaurant" search. Those live in `Synvya/client`.
- The systemtools-side Support management UI and the DynamoDB `support` flag. Those live in `systemtools` (frontend) and the Synvya server (backend, mirroring to Keycast).
- The contents of `ALLOWED_PUBKEYS`. The bootstrap manual-sync of Synvya leadership/engineering pubkeys and the systemtools service pubkey is operational, not a Keycast feature.

### What `Synvya/server` does not own

`Synvya/server` is not in the request path for any user-facing support action. The systemtools backend (which today lives inside `Synvya/server`) is in the path only for management operations (toggling the Support flag), not for the support actions themselves. The unused `KEYCAST_SERVICE_TOKEN` in `Synvya/server`'s config remains unused — it is replaced by NIP-98 signing with the systemtools service nsec.

---

## 3. API Changes in Keycast

### 3.1 Widen the `create_team` gate

Today, [`api/src/api/http/teams.rs:68`](../../api/src/api/http/teams.rs):

```rust
if !super::admin::is_full_admin(&auth) && !can_create_first_team {
    return Err(ApiError::forbidden(...));
}
```

Becomes:

```rust
if !super::admin::is_full_admin(&auth)
    && !super::admin::is_support_admin(&auth).await
    && !can_create_first_team
{
    return Err(ApiError::forbidden(...));
}
```

The existing `create_with_admin` repository call ([`core/src/repositories/team.rs:351`](../../core/src/repositories/team.rs)) inserts the caller as the team's `admin`, so a support user who creates a team gets full admin privileges on that team and can then call `add_key`, `add_authorization`, `add_user`, `invite_user`, etc. without further changes.

### 3.2 New endpoint: `POST /api/admin/teams/:id/support-access`

**Auth**: `is_support_admin()` only. Tenant-scoped via `TenantExtractor`.

**Path params**: `id` — team id.

**Request body**:
```json
{
  "policy_id": 42,           // optional; defaults to the team's "All Access" policy
  "label": "support: maria"  // optional; recorded on the authorization for audit clarity
}
```

**Behavior** (single transaction):
1. Look up the team and verify it belongs to the caller's tenant.
2. If the caller is not yet a `team_users` row for this team, insert one with `role = 'member'`. If the caller is already a member, leave the row alone (do not downgrade an admin).
3. Pick the team's first non-revoked stored key (this is the restaurant identity; teams have exactly one in the current Synvya model).
4. Mint a fresh `Authorization` against that stored key, with `connected_client_pubkey = caller`, derived bunker keys, and a fresh connection secret. Use the existing `auth_repo.create()` path so the signer daemon picks it up.
5. Return the bunker URL plus the authorization summary.

**Response**:
```json
{
  "team_id": 17,
  "stored_key_pubkey": "abcd...",
  "authorization": { /* AuthorizationCreatedResponse fields */ },
  "bunker_url": "bunker://..."
}
```

**Audit**: `tracing::info!("Support access granted: team={team_id} support_admin={pubkey} authorization={auth_id}")`.

### 3.3 New endpoint: `DELETE /api/admin/teams/:id/support-access`

**Auth**: `is_support_admin()` only. Tenant-scoped.

**Behavior** (single transaction):
1. Find all non-revoked authorizations on this team where `connected_client_pubkey = caller`. Set `revoked_at = NOW()` and `revoked_reason = 'support_session_end'` on each. Notify the signer daemon (`AuthorizationCommand::Remove`) for each one, mirroring [`admin.rs:1138`](../../api/src/api/http/admin.rs).
2. If the caller's `team_users` row has `role = 'member'` (not `admin`), remove it. If they are an `admin` of this team (e.g., they created it), leave the membership alone.
3. Return a count of revoked authorizations and a `removed_membership: bool`.

**Response**:
```json
{
  "team_id": 17,
  "revoked_authorizations": 1,
  "removed_membership": true
}
```

**Audit**: `tracing::info!("Support access released: team={team_id} support_admin={pubkey} revoked={count}")`.

### 3.4 Route registration

Both new routes are registered alongside the existing admin block at [`api/src/api/http/routes.rs:182`](../../api/src/api/http/routes.rs) under the `auth_cors` layer:

```rust
.route(
    "/admin/teams/:id/support-access",
    post(admin::grant_team_support_access)
        .delete(admin::release_team_support_access),
)
```

### 3.5 NIP-98 service-auth path on admin routes

Keycast already verifies kind:27235 (NIP-98) envelopes during NIP-98 login at [`api/src/api/http/auth.rs:559`](../../api/src/api/http/auth.rs) and stamps `admin_role: "full" | "support"` into the issued UCAN. This spec extends the same primitive to **any admin route**, not just login:

- A request carrying `Authorization: Nostr <base64(kind:27235 event)>` is verified the same way (signature valid, `u` tag matches request URL, `method` tag matches HTTP method, `created_at` within tolerance).
- If the signing pubkey is in `ALLOWED_PUBKEYS`, the request is treated as if it carried a full-admin UCAN. `is_full_admin()` returns true for that request.
- If the signing pubkey is in the `support_admins` Redis set, the request is treated as `admin_role: "support"`.
- Otherwise the envelope is rejected.

This middleware is the entry point the `systemtools` backend uses when it calls `POST /api/admin/support-admins`: the call is signed with the systemtools service nsec, and Keycast resolves the service pubkey to full-admin authority via this path. No session cookie, no shared secret token. Each request is independently authenticated by signature.

Keep the existing UCAN cookie path untouched — it remains the primary auth mechanism for human callers (Restaurant app, future systemtools UI calls that piggyback on a user's keycast session). NIP-98 service-auth is an additional path, not a replacement.

The middleware lives in `api/src/api/extractors.rs` (or a new file `api/src/api/nip98_extractor.rs`) and is composed into the same `UcanAuth` extractor so handlers do not need to know which path the request came in on.

---

## 4. Reused Surface (no changes)

The following are already implemented and gated on `is_support_admin()` ([`api/src/api/http/admin.rs`](../../api/src/api/http/admin.rs)). The Restaurant app will call them as-is:

| Endpoint | Use in support flow |
|---|---|
| `GET /api/admin/status` | After login, the client reads `role: "support"` to decide whether to show support UI |
| `GET /api/admin/user-lookup?q=` | Find a target user (restaurant owner) by email/username/pubkey |
| `GET /api/admin/user-teams?pubkey=` | List a target user's restaurants and their authorizations |
| `POST /api/admin/authorizations/:id/revoke` | Manual revoke for diagnostics; complements the bulk revoke in `DELETE .../support-access` |
| `GET /api/admin/claim-tokens?pubkey=` | Look up a pending claim token for handoff |
| `POST /api/admin/claim-tokens` | Generate a claim link to hand off the new restaurant to its owner |
| `POST /api/admin/support-admins` | Full-admin only. Called by the `systemtools` backend (NIP-98-signed by the systemtools service identity) when a `superadmin` toggles the Support flag on a user. Not called by humans directly in Phase 2. |
| `DELETE /api/admin/support-admins/:pubkey` | Full-admin only. Same caller as above; invoked on demotion. |

For team-internal operations after `create_team` (adding a stored key, creating the first server-side authorization for `Synvya/server`, inviting the actual owner by email), the support user uses the existing team-admin endpoints by virtue of being the team's admin. Specifically:

- `POST /api/teams/:id/keys` — add the restaurant's stored key.
- `POST /api/teams/:id/keys/:pubkey/authorizations` — mint the authorization the support user (or `Synvya/server`) will use for signing.
- `POST /api/teams/:id/invitations` — email the actual restaurant owner an invite to take over as admin.

---

## 5. Lifecycle

### 5.1 Provision a new restaurant (cold start)

```
Maria (support_admin)                    Restaurant app                   Keycast
  │                                            │                              │
  │─ login email/password ────────────────────►│                              │
  │                                            │─ POST /api/auth/login ──────►│
  │                                            │◄ UCAN { admin_role: support }│
  │                                            │                              │
  │                                            │─ GET /api/admin/status ─────►│
  │                                            │◄ { role: "support" }         │
  │                                            │                              │
  │   (picker shows "Create new restaurant")   │                              │
  │─ click ──────────────────────────────────►│                              │
  │   { name: "Joe's Diner" }                  │                              │
  │                                            │─ POST /api/teams ───────────►│
  │                                            │◄ team_id, Maria=admin        │
  │                                            │─ POST /teams/:id/keys ──────►│
  │                                            │◄ stored_key (restaurant id)  │
  │                                            │─ POST /authorizations ──────►│
  │                                            │◄ bunker_url                  │
  │                                            │   (connect bunker, sign as   │
  │                                            │    restaurant from now on)   │
  │ ... populate menu, profile, hours ...      │                              │
  │                                            │                              │
  │─ click "Hand off to owner" ───────────────►│                              │
  │   { owner_email: joe@... }                 │                              │
  │                                            │─ POST /teams/:id/invitations►│
  │                                            │◄ invitation sent             │
  │                                            │                              │
  │   (later: Joe accepts, becomes admin)      │                              │
  │   (later: Maria switches away, calls       │                              │
  │    DELETE /support-access — see 5.3)       │                              │
```

### 5.2 Open an existing restaurant for diagnostics

```
Maria                       Restaurant app                   Keycast
  │                              │                              │
  │─ search "Joe's Diner" ──────►│                              │
  │                              │─ GET /admin/user-lookup ────►│
  │                              │◄ candidates                  │
  │ pick a candidate user        │                              │
  │                              │─ GET /admin/user-teams ─────►│
  │                              │◄ teams + authorizations      │
  │ pick a team                  │                              │
  │                              │─ POST /admin/teams/:id/      │
  │                              │       support-access ───────►│
  │                              │◄ bunker_url                  │
  │                              │   (disconnect previous       │
  │                              │    bunker, connect to new,   │
  │                              │    active team = this one)   │
  │ ... fix the issue ...        │                              │
```

### 5.3 Release access (logout, switch, or timeout)

```
Restaurant app                                                  Keycast
      │                                                            │
      │─ DELETE /api/admin/teams/:id/support-access ──────────────►│
      │   (revokes Maria's active authorizations on this team,     │
      │    removes membership row if she was a `member`)           │
      │◄ { revoked_authorizations: 1, removed_membership: true }   │
```

The signer daemon receives `AuthorizationCommand::Remove` for each revoked authorization and drops the in-memory handler, so any subsequent NIP-46 traffic from Maria's bunker URL fails immediately. The audit log records both bookends (grant and release) with Maria's pubkey.

---

## 6. Restaurant Client Changes (`Synvya/client`)

Out-of-scope for this Keycast spec but listed for the cross-repo summary:

- After login, call `GET /api/admin/status`. If `role === "support"`, expose support UI.
- Replace the implicit "land on `/app/profile`" behavior with a restaurant picker when `role === "support"`. For `role === null` users (regular owners), keep current behavior.
- Picker shows current memberships from `listTeams()`, plus a "Create new restaurant" button and an "Open another restaurant" search.
- "Open another restaurant" → search via `user-lookup`/`user-teams` → pick a team → call `POST /api/admin/teams/:id/support-access` → connect the returned bunker URL.
- On active-team switch, logout, or session timeout, call `DELETE /api/admin/teams/:id/support-access` for the previous active team if it was a support session (i.e., not a team Maria is a permanent member or admin of).
- For provisioning (`POST /api/teams`), the existing `keycastClient.createTeam(...)` continues to work because the gate is widened, not replaced. No new client method needed for creation.

The `TeamSelector` component already supports the multi-team case; it renders only when `teams.length > 1`. The picker shell wraps it for the support flow.

---

## 7. Audit and Observability

Every support write operation emits a structured `tracing::info!` line with the support admin's pubkey, the target team, and the operation outcome. This mirrors the existing `revoke_authorization` log pattern at [`api/src/api/http/admin.rs:1154`](../../api/src/api/http/admin.rs).

Log lines added or relied upon:

- `Team created by support admin: team_id={team_id} support_admin={pubkey} name={name}` — emit from `create_team` when the gate path is `is_support_admin`.
- `Support access granted: team={team_id} support_admin={pubkey} authorization={auth_id}` — emit from `grant_team_support_access`.
- `Support access released: team={team_id} support_admin={pubkey} revoked={count}` — emit from `release_team_support_access`.
- Existing `Authorization {} revoked by admin {}` continues to fire for each individual revocation inside the release endpoint.

No structured audit table is added in this spec; the structured log lines feed Cloud Logging and are sufficient for the current support volume. A formal audit table is left to a future spec when volume justifies it.

---

## 8. Security Considerations

1. **Privilege scope**. A support admin gains write access to any team in the tenant via `support-access`, including teams where the actual owner is an admin. This is intentional — that is the support capability — but it must be paired with two operational controls: (a) `add_support_admin` is gated to full admins only, and (b) every grant/release is logged with the support admin's pubkey.

2. **JIT membership leak**. If `release_team_support_access` is never called (browser crashes, network failure, the support admin closes their laptop without logging out), the support admin remains a member with a live authorization until either (a) the authorization expires or (b) another support admin manually revokes via `revoke_authorization`. To bound this, support-issued authorizations are minted with a short `expires_at` (default 24h, configurable per call). The signer daemon enforces expiry.

3. **Restaurant owner visibility**. After this lands, a restaurant owner viewing their team membership list will see support admins listed alongside the owner during active support sessions. This is a feature, not a leak, but the Restaurant app should label support members distinctly so owners are not confused about who has access. The label is applied client-side based on `team_users.role = 'member'` plus a presence check against the `support_admins` set (read via `GET /api/admin/support-admins` if owner has visibility, or returned inline by `user-teams` for support; this is a client UX decision and out of scope for Keycast).

4. **Audit trail tampering**. Support admins cannot delete or amend their own log lines; logs go to Cloud Logging via the standard request path.

5. **Stored key access**. Support admins never touch the restaurant's stored secret key directly. They sign via NIP-46 against an authorization they hold, exactly like any other team member. The encryption-at-rest model is unchanged.

6. **Systemtools service identity**. The systemtools service nsec is a full-admin credential — anyone holding it can do anything in Keycast. It must be stored only in AWS Secrets Manager, never logged, never passed through frontend code, and never used outside the systemtools backend. Compromise of this nsec is equivalent to compromise of a Keycast root credential and is handled by rotating the value in Secrets Manager and updating `synvya/{env}/keycast/allowed-pubkeys`.

7. **Demotion is eventually consistent**. When a `superadmin` removes the Support flag from a user, the user's UCAN may still carry `admin_role: "support"` until it expires (UCANs are stamped at login, not re-checked on every request). For immediate revocation, the systemtools backend should also revoke the user's active Keycast sessions via existing session-management endpoints, or accept that Support powers persist until UCAN expiry. The current Keycast UCAN TTL is short enough (minutes) that this is acceptable for normal demotions; emergency demotions (terminated employees) require explicit session revocation.

---

## 9. Implementation Checklist

Keycast (`synvya-staging` branch):

- [ ] Widen `create_team` gate at [`api/src/api/http/teams.rs:68`](../../api/src/api/http/teams.rs) to call `is_support_admin().await`.
- [ ] Add `grant_team_support_access` handler in [`api/src/api/http/admin.rs`](../../api/src/api/http/admin.rs).
- [ ] Add `release_team_support_access` handler in the same file.
- [ ] Register both routes under `/admin/teams/:id/support-access` in [`api/src/api/http/routes.rs`](../../api/src/api/http/routes.rs).
- [ ] Add NIP-98 service-auth extractor (§3.5) and compose it into `UcanAuth` so any admin route accepts either a UCAN cookie or a request-bound NIP-98 envelope.
- [ ] Add structured log lines per §7.
- [ ] Default authorization expiry of 24h on support-issued authorizations (per §8.2). Make configurable via request body.
- [ ] Tests:
  - [ ] support admin can create a team; non-admin non-support user with one existing team membership cannot.
  - [ ] support admin can grant + release access on a team they are not a member of; second release is a no-op.
  - [ ] release does not remove `admin` membership (e.g., the support user who originally created the team).
  - [ ] release notifies the signer daemon (`AuthorizationCommand::Remove`).
  - [ ] full admin retains all current capabilities.
  - [ ] non-support, non-admin caller is forbidden on both new endpoints.
  - [ ] NIP-98-signed call from a pubkey in `ALLOWED_PUBKEYS` resolves to full-admin and can `POST /api/admin/support-admins`.
  - [ ] NIP-98-signed call from a pubkey not in `ALLOWED_PUBKEYS` and not in `support_admins` is rejected.
  - [ ] NIP-98 envelope with mismatched `u` tag, mismatched `method` tag, or stale `created_at` is rejected.

Restaurant app (`Synvya/client`, separate PR):

- [ ] Read `role` from `GET /api/admin/status` on auth init.
- [ ] Picker shell with "Create new restaurant" and "Open another restaurant" actions when `role === "support"`.
- [ ] Wire "Open another restaurant" to `user-lookup` → `user-teams` → `support-access`.
- [ ] On active-team switch / logout, call `DELETE .../support-access` if the leaving team was a support session.
- [ ] Distinct UI label for support members on the Team page.

`systemtools` and Synvya server backend (separate PR):

- [ ] Add `support: boolean` attribute to `synvya-{env}-admin-users` DynamoDB items (default false on existing rows).
- [ ] Add `support` to the `AdminUser` TypeScript type and the `SessionInfo` shape returned by `GET /api/admin/me`.
- [ ] Render a "Support" toggle in the systemtools admin user management page (already a Phase 4 placeholder), gated on `superadmin` role.
- [ ] Backend handler for the toggle: write DynamoDB, then call Keycast `POST /api/admin/support-admins` (or `DELETE /api/admin/support-admins/:pubkey` on demotion) with NIP-98 signing.
- [ ] `KeycastAdminClient` service (~150 LOC): holds the systemtools service nsec from AWS Secrets Manager; signs each call with NIP-98 (URL + method + timestamp tags); retries with exponential backoff on transient errors.
- [ ] Idempotency: if the DynamoDB write succeeds but the Keycast mirror call fails, the toggle is marked "drift" and a sweeper job reconciles. Drift is also surfaced in the admin UI as a warning.
- [ ] Tests: end-to-end toggle promotes/demotes the user in both DynamoDB and Keycast Redis; failure of the Keycast call is captured as drift; idempotent re-toggle is a no-op.

Operations:

- [ ] Generate the systemtools service nsec; store as `synvya/{env}/systemtools/keycast-service-key` in AWS Secrets Manager.
- [ ] Add the corresponding pubkey to `synvya/{env}/keycast/allowed-pubkeys` alongside the existing bootstrap pubkeys.
- [ ] Document the manual sync runbook for adding/removing Synvya leadership/engineering pubkeys to/from `allowed-pubkeys`.

---

## 10. Out of Scope / Future Work

- **Tenant-scoped support admins**. Today the `support_admins` Redis set is keyed `support_admins` (single key). If Keycast becomes multi-tenant in Synvya, the set should be namespaced per tenant (`support_admins:{tenant_id}`) and `is_support_admin` should consult the caller's tenant. Not needed yet.
- **Automatic ALLOWED_PUBKEYS sync**. Bootstrap full-admin membership is intentionally manual. Removing this manual step would either require systemtools to manage `ALLOWED_PUBKEYS` (which would mean systemtools could elevate itself or any of its users to Keycast full admin — a much larger blast radius than the Support flag), or a separate identity system. Both are larger than the problem currently warrants.
- **Auto-expire of stale support sessions**. Beyond the 24h authorization expiry, a periodic sweeper that revokes any `support` authorizations older than N hours would reduce the leak surface in §8.2. Defer until we see real volume.
- **Read-only support mode**. A support admin could be granted "view this team's data" without minting a signing authorization. Not in this spec — current Synvya support tasks are write-leaning (fix bad menu data, repair profile fields).
- **Formal audit table**. Once support volume justifies it, move from `tracing::info!` to a structured `admin_audit_log` table with `(actor_pubkey, action, target_team_id, target_authorization_id, outcome, ts, request_id)` columns.
- **Support team identity**. Synvya may eventually want a "Synvya Support" Nostr identity that signs outbound communications. That is a separate decision unrelated to this spec; the same way `systemtools` chose against a shared admin team identity, this spec does not introduce one. Each support action carries the acting admin's personal pubkey.

---

## 11. Operational: Defining Support Agents

This section is the runbook for the management surface introduced in §1 ("Defining who is a support agent") and §2 ("What `systemtools` owns").

### Roles in play

| Role | Where defined | Manages | Bootstrap |
|---|---|---|---|
| **Keycast full admin** | Pubkey listed in `ALLOWED_PUBKEYS` env var, sourced from `synvya/{env}/keycast/allowed-pubkeys` secret | Direct full Keycast authority; can promote/demote support admins, run admin scripts, read/write any team | **Manual.** Edit the secret, redeploy/refresh. |
| **Keycast support admin** | Pubkey in Redis `support_admins` set | Acts as any restaurant identity in the tenant; creates new restaurant teams; uses `is_support_admin`-gated read/write endpoints | **Automatic** via systemtools mirror (see below). |
| **`systemtools` `superadmin`** | DynamoDB row in `synvya-{env}-admin-users` with `role: 'superadmin'` | Manages `systemtools` admin users, including toggling the Support flag | **Manual.** Existing systemtools admin management. Independent of Keycast full admin. |
| **`systemtools` Support flag** | DynamoDB row with `support: true` | When toggled, drives the Keycast support-admins mirror call | Toggled by a `systemtools` `superadmin` in the systemtools UI. |

A single Synvya employee can hold any combination: e.g., an engineer might be a Keycast full admin (in `ALLOWED_PUBKEYS`) *and* a systemtools `superadmin` *and* have the Support flag, while a customer-facing agent might only have the Support flag (with role `pulse_only` or `admin` to retain systemtools UI access for their day job).

### Promotion flow (toggle Support flag on)

1. Synvya `superadmin` opens the `systemtools` admin user page for the target user.
2. Toggles the **Support** checkbox to on.
3. `systemtools` backend writes `support: true` to the DynamoDB row.
4. `systemtools` backend builds a kind:27235 NIP-98 envelope: `u` = `https://auth.synvya.com/api/admin/support-admins`, `method` = `POST`, signed with the systemtools service nsec.
5. `systemtools` backend sends `POST /api/admin/support-admins` to Keycast with `Authorization: Nostr <base64(envelope)>` and body `{ "identifier": "<target user's pubkey or email>" }`.
6. Keycast verifies the envelope, resolves the systemtools service pubkey to full-admin via `ALLOWED_PUBKEYS`, runs the existing `add_support_admin` handler, and writes to Redis.
7. Next time the target user logs into Keycast, `is_support_admin()` returns true and their UCAN carries `admin_role: "support"`.

### Demotion flow (toggle Support flag off)

Symmetric to promotion: DynamoDB write, then `DELETE /api/admin/support-admins/:pubkey` with NIP-98 signing. The Redis set membership is removed. Existing user UCANs may still carry the `support` role until they expire — see §8.7 for the eventual-consistency note.

### Bootstrap (one-time, per environment)

Run once when standing up a new staging or production environment, or when rotating credentials:

1. Generate a fresh nsec for the systemtools service identity.
2. Store as `synvya/{env}/systemtools/keycast-service-key` in AWS Secrets Manager.
3. Compute the corresponding hex pubkey.
4. Edit `synvya/{env}/keycast/allowed-pubkeys` to append the systemtools service pubkey alongside the existing bootstrap human pubkeys.
5. Redeploy or trigger the secret-refresh path on Keycast so the new `ALLOWED_PUBKEYS` is loaded.
6. Verify by issuing a test NIP-98-signed `GET /api/admin/support-admins` from the systemtools backend and confirming a `200` response.

### Adding or removing a Synvya leadership/engineering full admin

This is **manual** by design (§10). Steps:

1. Edit `synvya/{env}/keycast/allowed-pubkeys` to add or remove the human's hex pubkey.
2. Redeploy or trigger secret refresh on Keycast.
3. The change takes effect on the next request that re-reads `ALLOWED_PUBKEYS`. Existing UCANs already issued to that pubkey carry the role until they expire.

There is no UI for this. It is a deliberate, low-frequency operation tied to the secret-management workflow.
