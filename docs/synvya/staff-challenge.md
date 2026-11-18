# The staff challenge

**Reality:** Built on `murali-dev`, 2026-11-18. Not on `synvya-staging` or `synvya` yet.
**Verified against:** `api/src/api/http/staff_challenge.rs`, `api/tests/staff_challenge_test.rs`, `scripts/load-secrets.sh`, Synvya Server's `src/services/staff/` and `src/api/routes/staff.ts`.

Synvya-only. Synvya Server's staff session names a person by their own key in the owner tenant. To get it, the person signs a server challenge with that key ([server store-vertical-server.md §15](https://github.com/Synvya/server/blob/staging/docs/specs/store-vertical-server.md)). The account app holds a Keycast login session, which cannot sign with the person's key: `/api/user/sign` needs an OAuth or bunker authorization for the app's origin. This route signs that one challenge, and nothing else, for a session from a listed origin.

## 1. The route

`POST /api/user/staff-challenge/sign`, with the UCAN session cookie or Bearer token, CORS as the other `/api/user/*` routes (`ALLOWED_ORIGINS`, with credentials).

Body: `{ "challenge_id", "nonce", "expires_at" }`, each 1 to 128 printable ASCII characters with no space. Keycast builds the event:

| Field | Value |
|---|---|
| `kind` | 27235 |
| `pubkey` | the session's person |
| `created_at` | now |
| `content` | empty |
| `tags` | exactly `["challenge_id", …]`, `["nonce", …]`, `["person_pubkey", <the person's key>]`, `["expires_at", …]`, in that order |

200: `{ "signed_event": <event> }`. The person's key is decrypted for the one signature.

| Status | When |
|---|---|
| 401 | No session, or the session is not valid for this tenant |
| 403 | The session's origin (the UCAN's `redirect_origin`) is not in `STAFF_CHALLENGE_ORIGINS` |
| 400 | A value is empty, too long, or holds a space or a control character |
| 404 | On the customer hostname (`customer_tenant_guard`) |

## 2. Configuration

`STAFF_CHALLENGE_ORIGINS`: exact bare origins, comma-separated. No path, no trailing slash, no wildcard. Unset or empty signs nothing. When `NODE_ENV` is `staging` or `production`, every entry must be `https` unless `ALLOW_LOCALHOST_ORIGINS=true`, or Keycast refuses to start. An `http` entry, wherever it is accepted, must name `localhost` or a host under `local.synvya.com`.

`ALLOW_LOCALHOST_ORIGINS` is the existing staging-only switch that lets local apps through CORS. Staging and production both run `NODE_ENV=production`, so this switch, not the node environment, is what tells them apart. Production sets it `false` (`scripts/load-secrets.sh`).

| Environment | Value | Set in |
|---|---|---|
| Local | `http://account.local.synvya.com:5273` | `.env.local` |
| Staging | `https://account.staging.synvya.com,http://account.local.synvya.com:5273` | `scripts/load-secrets.sh` |
| Production | `https://account.synvya.com` | `scripts/load-secrets.sh` |

Staging lists the local account app so a developer can run it against staging with staging credentials (decided 2026-11-18). A session the person opened on `https://account.staging.synvya.com` is still refused from the local app: a session's origin is fixed at login.

## 3. Security

| Risk | What holds it |
|---|---|
| The signed event used as another credential | Keycast builds the event, so the caller chooses no tag. Synvya Server's admin sign-in needs an `admin_pubkey` tag and its merchant sign-in a `merchant_pubkey` tag; NIP-98 (Keycast's own admin login, divine names) needs `u` and `method`. The event carries none of these, so only the staff sign-in accepts it |
| Replay | The server's challenge is single use and expires in 2 minutes; the nonce and challenge id are the server's |
| A page on another origin | The session cookie is `SameSite=Lax` and CORS allows only `ALLOWED_ORIGINS`. On top of that, the session's own origin must be listed here, so a session made by the admin or diners app cannot use the route |
| Script injected into a listed origin | It can get a staff session for the signed-in person. The same session cookie can already mint a signing authorization for every team key the person holds (`/api/teams/:id/keys/:pubkey/authorizations`), which is more power than a staff session. The route adds no capability that script did not have |
| A local origin left on production | Startup refuses an `http` entry when `NODE_ENV` is `staging` or `production` and `ALLOW_LOCALHOST_ORIGINS` is not `true`. Production's `ALLOW_LOCALHOST_ORIGINS=false` is the one setting to keep; keycast#107 checks it after each deploy |
| The local origin on staging | Any page served as `http://account.local.synvya.com:5273` on the developer's machine (the name points to 127.0.0.1) can get a staff session for a person who logged in there. The reach is staging data only, and the same session cookie can already mint team-key authorizations from that origin, which staging allows through CORS. An `http` entry must name a local host, so a public `http` origin cannot be listed by mistake |
| Audit | Each signature logs `staff_challenge_signed` with the tenant, origin and person. Each refusal for the origin logs `staff_challenge_refused` |

**Why not `/api/user/sign` with a new rule.** That route signs any event the caller sends. A rule there that let first-party sessions sign kind 27235 would sign the server's admin challenge too. A separate route that builds its own event cannot.

**Why not a personal bunker per device** (`/user/bunker/create`). It leaves an authorization row per device with the person's full key behind it, and it refuses `http` origins, so the local stack could not use it.

## 4. Fork note

The handler and its configuration are in `staff_challenge.rs`, a file upstream does not have. Upstream files change by one route registration in `routes.rs`, one module line in `mod.rs` and one startup check in `keycast/src/main.rs`. It is not proposed upstream.
