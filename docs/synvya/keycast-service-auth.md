# Keycast Service Auth

Keycast-vantage-point spec for the cross-repo "Keycast service auth" foundation. Defines how Keycast accepts authenticated, request-bound NIP-98 envelopes on admin routes and resolves them to a full-admin context when the signing pubkey is in `ALLOWED_PUBKEYS`.

The same foundation has parallel specs in the other repos:

- [Cross-system `keycast-service-auth.md`](https://github.com/Synvya/docs/blob/main/architecture/keycast-service-auth.md) — system-wide rationale and trust model.
- [Server `keycast-service-auth.md`](https://github.com/Synvya/server/blob/staging/docs/specs/keycast-service-auth.md) — TypeScript implementation of the `KeycastAdminClient` that signs envelopes.

**System context** (Keycast):

- [Architecture Context](architecture-context.md)
- [Keycast Boundary](specs/keycast-boundary.md)
- [Support Users](support-users.md) — first consumer of this foundation.

---

## 1. Scope

Keycast already verifies kind:27235 (NIP-98) envelopes during NIP-98 login at [`api/src/api/http/auth.rs:559`](../../api/src/api/http/auth.rs) and stamps `admin_role: "full" | "support"` into the issued UCAN cookie. After login, all subsequent admin requests are authorized by that cookie via the `UcanAuth` extractor.

This spec extends the same NIP-98 primitive to **any admin route, not just login**. A request that arrives carrying a NIP-98 envelope in the `Authorization: Nostr ...` header is verified per-request and resolved to an `admin_role` directly, without going through login or holding a cookie.

The new path is **additive**. It does not replace the UCAN cookie path. Existing callers (browsers, Restaurant app, systemtools UI) continue to work unchanged.

## 2. Receiving Surface

The new auth path is composed into the existing `UcanAuth` extractor. Handlers do not need to know which path the request came in on — they read `auth.pubkey` and `auth.admin_role` exactly as today.

```
Existing path:  UCAN cookie  → UcanAuth { pubkey, admin_role }
New path:       NIP-98 header → UcanAuth { pubkey, admin_role }
                                       ▲
                                       │
                       composed into UcanAuth so all admin routes
                       accept either path transparently
```

The composition order:

1. If `Authorization: Nostr <base64-event>` is present, attempt NIP-98 verification.
2. If verification succeeds, resolve `admin_role` from `ALLOWED_PUBKEYS` / `support_admins` Redis set, and return `UcanAuth`.
3. Otherwise, fall back to the existing UCAN cookie path.
4. If neither resolves, return 401.

## 3. NIP-98 Verification

For each request bearing the NIP-98 header, verify in this order:

1. The header value parses as `Nostr <base64>`. Decode the base64 to a JSON string, parse to a Nostr event.
2. The event's `kind` is `27235`.
3. The event's signature is valid for the claimed pubkey.
4. The event has a `u` tag whose value matches the request's full URL (scheme, host, path, query — exactly).
5. The event has a `method` tag whose value matches the HTTP method (uppercase).
6. The event's `created_at` is within ±60 seconds of the server's clock.
7. The event has not been seen before (anti-replay) — see §5.

If any check fails, return 401 with a generic `unauthorized` body. Do not leak which specific check failed.

## 4. Pubkey Resolution

Once the envelope is verified, the signing pubkey is resolved to an admin role using the existing helpers in [`api/src/api/http/admin.rs:29`](../../api/src/api/http/admin.rs):

- `is_full_admin(pubkey)` — pubkey is in `ALLOWED_PUBKEYS` env var (sourced from `synvya/{env}/keycast/allowed-pubkeys`), or the carried role is `full`.
- `is_support_admin(pubkey)` — pubkey is in the `support_admins` Redis set (or the caller is already a full admin).

The resulting `UcanAuth` carries:

- `pubkey`: the verified pubkey from the envelope.
- `admin_role`: `Some("full")`, `Some("support")`, or `None`.

If `admin_role` is `None` (pubkey is recognized neither as full admin nor support admin), the handler that consumes `UcanAuth` may still see the request — the same as today for an authenticated non-admin user. Routes that require admin already check `is_full_admin`/`is_support_admin` themselves; this spec does not change those checks.

## 5. Anti-Replay

The Synvya server signs every admin call with a fresh `created_at`. To prevent envelope reuse, Keycast tracks recently-seen envelope IDs.

- Compute the event id per NIP-01 (sha256 of canonical event serialization).
- Store the id in Redis with a TTL slightly longer than the `created_at` tolerance window (e.g. `EXPIRE 120` seconds).
- On each verification, `SET NX` on the id key. If the key already existed, reject as a replay.

If Redis is unavailable, the verification falls back to "accept" — no replay protection, but the request still proceeds. This matches how `is_support_admin()` already handles Redis outages: log a warning, do not block.

## 6. Performance

The NIP-98 verification path is invoked only on requests that arrive with the header — i.e., only the Synvya server's outbound calls. Browser traffic continues to use the cookie path and is unaffected.

Per-request cost: one signature check (~50 µs on Curve25519), one `ALLOWED_PUBKEYS` string scan, one Redis `SET NX` (anti-replay). All bounded; suitable for the call frequency expected (admin operations are infrequent).

## 7. Bootstrap

The server pubkey (derived from `SERVER_BUNKER_CLIENT_PRIVATE_KEY`) must be in `ALLOWED_PUBKEYS` for verification to resolve to full admin. Bootstrap procedure:

1. Read the existing nsec from `synvya/{env}/server/bunker-client-private-key` (managed by Synvya server ops; see [server spec](https://github.com/Synvya/server/blob/staging/docs/specs/keycast-service-auth.md)).
2. Derive the hex pubkey.
3. Append the pubkey to `synvya/{env}/keycast/allowed-pubkeys`. Existing bootstrap human pubkeys remain in place.
4. Refresh the secret on the running Keycast process (deployment or in-process refresh, depending on environment).

`ALLOWED_PUBKEYS` parsing is unchanged — see [`admin.rs:34`](../../api/src/api/http/admin.rs).

## 8. Implementation Checklist

- [ ] New module under `api/src/api/` (e.g. `nip98_extractor.rs`, or extend `extractors.rs`) implementing the verification + resolution flow per §3 and §4.
- [ ] Compose into `UcanAuth` extractor at [`api/src/api/extractors.rs:62`](../../api/src/api/extractors.rs) so any handler accepting `UcanAuth` accepts either NIP-98 header or UCAN cookie.
- [ ] Anti-replay store using the existing Redis client (already wired into `KeycastState`).
- [ ] Tests:
  - [ ] Valid envelope from a pubkey in `ALLOWED_PUBKEYS` → `admin_role: "full"`.
  - [ ] Valid envelope from a pubkey in `support_admins` Redis → `admin_role: "support"`.
  - [ ] Valid envelope from a known but non-admin pubkey → `admin_role: None`, request proceeds (handler may still reject).
  - [ ] Mismatched `u` tag → 401.
  - [ ] Mismatched `method` tag → 401.
  - [ ] Stale `created_at` → 401.
  - [ ] Tampered signature → 401.
  - [ ] Replayed envelope (same id within TTL) → 401.
  - [ ] Redis unavailable during anti-replay check → request proceeds (warning logged).
  - [ ] UCAN cookie still works on routes that previously accepted it.

## 9. Out of Scope

- The actual admin endpoints called via this path (`add_support_admin`, `preload_user`, etc.) — those exist or are added by their consumer specs ([Support Users](support-users.md), `admin-user-provisioning`).
- Per-call human-attribution headers (`X-Acting-As`). A future enhancement; not in v1.
- Tenant-scoping of the recognition path. The current `support_admins` set and `ALLOWED_PUBKEYS` are global. If multi-tenant operator separation becomes a requirement, both stores need namespacing — a separate spec.

## 10. Consumer Specs

The following specs build on this foundation and assume the NIP-98 service-auth path is in place:

- [Support Users](support-users.md) — uses NIP-98 service auth so the Synvya server can mirror Support flag toggles into the `support_admins` Redis set.
- `admin-user-provisioning` (forthcoming) — uses NIP-98 service auth so the server can call `preload_user` and `claim-tokens` on behalf of `systemtools` superadmins.
