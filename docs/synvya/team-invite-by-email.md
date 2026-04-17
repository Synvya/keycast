# Team Invite by Email

Spec for email-based team invitations in Keycast. Adds a `team_invitations` table, an invite endpoint that sends email to new users (or instantly adds existing users), and an accept flow that converts a token into team membership.

**Issue**: [Synvya/client#365](https://github.com/Synvya/client/issues/365)

**System context**:
- [Keycast Boundary](keycast-boundary.md)
- [Cross-repo: Team Invite by Email](https://github.com/Synvya/docs/blob/main/architecture/team-invite-by-email.md) — sequence diagrams and contract between repos

---

## 1. Scope

Keycast already owns team membership (`POST /teams/:id/users`). This feature extends that ownership to include invitation lifecycle: creation, email delivery, preview, acceptance, revocation, and expiry.

### What Keycast owns (new)
- `team_invitations` table and all CRUD
- Email delivery of invitation links
- Token validation and acceptance (resolving token → team membership)
- Invitation preview for unauthenticated users (enough to render a landing page)

### What Keycast does NOT own
- The invitation landing page UI (that's the client)
- Deciding where the invite link points (client provides the base URL, or it's derived from the tenant's configured redirect origin)

## 2. Data Model

### 2.1 New Table: `team_invitations`

```sql
CREATE TABLE team_invitations (
    id              SERIAL PRIMARY KEY,
    team_id         INT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL,
    email           VARCHAR(255) NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'member',
    token           VARCHAR(64) NOT NULL UNIQUE,
    invited_by      VARCHAR(64) NOT NULL,   -- hex pubkey of the admin who sent the invite
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ,
    accepted_by     VARCHAR(64),            -- hex pubkey of the user who accepted
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_invitation_role CHECK (role IN ('admin', 'member'))
);

CREATE INDEX idx_team_invitations_token ON team_invitations(token);
CREATE INDEX idx_team_invitations_team ON team_invitations(team_id);

-- Partial unique index: only one pending invite per email per team
-- Allows re-inviting after revocation or expiry (application checks expires_at)
CREATE UNIQUE INDEX uq_pending_invite
    ON team_invitations(team_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
```

Token generation: 32 random bytes, hex-encoded (64 chars). Use the same `generate_claim_token` pattern from `keycast_core::types::claim_token`.

Invitation expiry: **7 days** from creation.

### 2.2 Rust Types

```rust
// keycast_core/src/types/team_invitation.rs

pub struct TeamInvitation {
    pub id: i32,
    pub team_id: i32,
    pub tenant_id: i64,
    pub email: String,
    pub role: String,
    pub token: String,
    pub invited_by: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_by: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TeamInvitation {
    pub fn is_pending(&self) -> bool {
        self.accepted_at.is_none()
            && self.revoked_at.is_none()
            && self.expires_at > Utc::now()
    }
}
```

### 2.3 Repository

```rust
// keycast_core/src/repositories/team_invitation.rs

pub struct TeamInvitationRepository { pool: PgPool }

impl TeamInvitationRepository {
    pub async fn create(...) -> Result<TeamInvitation>;
    pub async fn find_by_token(token: &str) -> Result<Option<TeamInvitation>>;
    pub async fn find_valid_by_token(token: &str) -> Result<Option<TeamInvitation>>;
    pub async fn list_by_team(team_id: i32, tenant_id: i64) -> Result<Vec<TeamInvitation>>;
    pub async fn find_pending_by_email(team_id: i32, email: &str) -> Result<Option<TeamInvitation>>;
    pub async fn accept(token: &str, accepted_by: &str) -> Result<()>;
    pub async fn revoke(id: i32, team_id: i32, tenant_id: i64) -> Result<()>;
}
```

`find_valid_by_token` returns `Some` only if `accepted_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()`.

## 3. Endpoints

### 3.1 `POST /api/teams/:id/invite`

**Auth**: UCAN session (requires team admin).

**Request**:
```json
{ "email": "manager@restaurant.com", "role": "Member" }
```

**Logic**:

```
1. Verify caller is admin of team :id
2. Normalize email (lowercase, trim)
3. Validate email format
4. Check if email belongs to the calling user → 400 "Cannot invite yourself"
5. Look up user by email in this tenant:
   a. User exists:
      - Check if already a team member → 409 "Already a team member"
      - Add to team via TeamRepository::add_member
      - Return { status: "added", member: { ... } }
   b. User does not exist:
      - Check for existing pending invitation for this email+team → 409 "Invitation already pending"
      - Generate token (32 random bytes, hex)
      - Insert into team_invitations
      - Build invite URL: {client_origin}/accept-invite?token={token}
      - Send invitation email via EmailSender::send_team_invite_email
      - Return { status: "invited", invitation: { ... } }
```

**Response codes**: 200 (success), 400 (bad input), 409 (conflict), 403 (not admin).

### 3.2 `GET /api/teams/:id/invitations`

**Auth**: UCAN session (requires team admin).

Returns all invitations for the team (pending, accepted, revoked, expired). Client filters as needed.

**Response**:
```json
[
  {
    "id": 42,
    "email": "manager@restaurant.com",
    "role": "Member",
    "invited_by": "Alejandro",
    "created_at": "2026-04-12T...",
    "expires_at": "2026-04-19T...",
    "accepted_at": null,
    "revoked_at": null
  }
]
```

The `invited_by` field is resolved to a display name (from `user_profiles`) for the response. Falls back to truncated pubkey if no profile exists.

### 3.3 `DELETE /api/teams/:id/invitations/:invitation_id`

**Auth**: UCAN session (requires team admin).

Sets `revoked_at = NOW()` on the invitation. Only works if the invitation is still pending (not yet accepted, not yet revoked, not expired).

**Response**: 204 No Content.

### 3.4 `GET /api/invitations/preview?token=...`

**Auth**: None (public endpoint).

Returns enough data for the client to render the invite landing page without authentication.

**Response**:
```json
{
  "team_name": "Taqueria La Estrella",
  "team_key_pubkey": "5e7f...",
  "role": "Member",
  "invited_by_display_name": "Alejandro",
  "invited_by_email": "alejandro@synvya.com",
  "expires_at": "2026-04-19T...",
  "email": "muralirk@gmail.com"
}
```

Returns 404 if the token is invalid, expired, accepted, or revoked. The response intentionally omits the token itself (it's already in the query string).

The `email` field echoes the invitation's stored email so the client can prefill and lock the email field on the signup/login forms. This prevents the invitee from registering a Synvya account with a different address and hitting a 403 at `POST /api/invitations/accept`.

The `team_key_pubkey` field is the hex pubkey of the team's primary stored key (the signer behind the team's Nostr identity). The client uses it to fetch the team's kind-0 profile from relays and render a display name + avatar instead of the raw `team_name` handle. `null` if the team has no stored key yet.

The `invited_by_email` field is the inviter's Keycast user email. Lets the client render `"alejandro@synvya.com invited you to join..."` instead of a truncated pubkey. `null` if the inviter's account has no email on file.

**Security**: This endpoint leaks the team name, team signing pubkey, inviter name, inviter email, and invited email to anyone holding the token. Since tokens are 256-bit random and only delivered via email, the token holder is already authorized to act on the invitation. Exposing `invited_by_email` is acceptable in this flow — the inviter explicitly chose to invite this person — but is a deliberate widening relative to the prior response shape.

### 3.5 `POST /api/invitations/accept`

**Auth**: UCAN session (authenticated user).

**Request**:
```json
{ "token": "abc123..." }
```

**Logic**:
```
1. Validate token → find_valid_by_token
2. Token not found or not pending → 404 / 410 Gone
3. Get authenticated user's email from session
4. Compare with invitation email (case-insensitive) → 403 if mismatch
5. Check if user is already a team member → 409
6. Add user to team with invitation's role
7. Mark invitation as accepted (accepted_at = NOW(), accepted_by = user pubkey)
8. Return { team_id, role }
```

**Response codes**: 200 (success), 403 (email mismatch), 404 (invalid, expired, or already used token), 409 (already member).

## 4. Email

### 4.1 EmailSender Trait Extension

Add to the existing `EmailSender` trait:

```rust
async fn send_team_invite_email(
    &self,
    to_email: &str,
    team_name: &str,
    inviter_name: &str,
    role: &str,
    invite_url: &str,
) -> Result<(), String>;
```

### 4.2 Email Content

**Subject**: "You've been invited to join {team_name} on Synvya"

**Body** (key elements):
- "{inviter_name} has invited you to join **{team_name}** as a **{role}**."
- CTA button: "Accept Invitation" → `{invite_url}`
- Footer: "This invitation expires in 7 days. If you didn't expect this email, you can safely ignore it."

Use the same HTML email template style as existing verification and password-reset emails.

### 4.3 Invite URL Construction

The invite URL must point to the client app, not to a Keycast-hosted page. Derive the base URL from the tenant's configured redirect origin or from a new `INVITE_BASE_URL` env var:

```
{INVITE_BASE_URL}/accept-invite?token={token}
```

For the Synvya tenant: `https://account.synvya.com/accept-invite?token=...`
For staging: `https://account.staging.synvya.com/accept-invite?token=...`

## 5. CORS

- `POST /teams/:id/invite`, `GET /teams/:id/invitations`, `DELETE /teams/:id/invitations/:id` — same CORS as existing team routes (first-party `auth_cors`).
- `GET /invitations/preview` — public CORS (no auth, called from client before login).
- `POST /invitations/accept` — first-party `auth_cors` (requires session cookie).

## 6. Routing

Added to `routes.rs`:

```rust
// Under team_routes (existing, auth_cors):
.route("/teams/:id/invite", post(teams::invite_user))
.route("/teams/:id/invitations", get(teams::list_invitations))
.route("/teams/:id/invitations/:invitation_id", delete(teams::revoke_invitation))

// Separate routers for different CORS/auth requirements:
let invitation_preview_route = Router::new()
    .route("/invitations/preview", get(teams::preview_invitation))  // public_cors, no auth
    .with_state(pool.clone());

let invitation_accept_route = Router::new()
    .route("/invitations/accept", post(teams::accept_invitation))   // auth_cors, session required
    .with_state(pool);
```

## 7. Security Considerations

| Concern | Mitigation |
|---|---|
| Token brute-force | 256-bit random tokens (64 hex chars). Rate-limit preview/accept endpoints |
| Email enumeration via invite | The `invite` endpoint requires admin auth. The response distinguishes "added" vs "invited" only to the admin, which is acceptable since the admin already knows their team members |
| Preview leaks team name | Acceptable given token entropy. No PII beyond team name and inviter display name |
| Invitation to wrong person | Accept endpoint verifies authenticated user's email matches invitation email |
| Replay after acceptance | `accepted_at` is set; `find_valid_by_token` excludes accepted tokens |

## 8. Relationship to Existing Endpoints

- `POST /teams/:id/users` (add by pubkey) **remains unchanged**. It continues to work for programmatic/admin use. The new `invite` endpoint calls the same `TeamRepository::add_member` internally when the user already exists.
- The claim-token system (`/claim`, `/admin/claim-tokens`) is separate — it's for Vine-imported preloaded accounts, not team invitations.
- The `EmailSender` trait gains one new method; existing email types are untouched.

## 9. Team Member Email in Roster Responses

Follow-on to the invitation flow. Once a member joins (either instantly via the "added" branch of `POST /teams/:id/invite` or after accepting an invitation), the client's Team Settings view needs to identify them by email instead of by truncated pubkey. See the client-side spec [§ 9](https://github.com/Synvya/client/blob/main/docs/specs/team-invite-by-email.md) for the UI rendering.

### 9.1 Scope

Extend the `TeamUser` serialization returned by team-membership endpoints to include the member's email. No new endpoints, no new permissions, no new auth surface.

### 9.2 Wire Change

Add `email` to every response that currently serializes `TeamUser`:

```json
{
  "team_id": 5,
  "user_pubkey": "abc...",
  "role": "Admin",
  "email": "manager@restaurant.com",
  "created_at": "...",
  "updated_at": "..."
}
```

Affected endpoints (all already team-admin or team-member authenticated):

| Endpoint | Where `TeamUser` appears |
|---|---|
| `GET /api/teams` | `team_users[]` inside each team |
| `POST /api/teams/:id/users` | Response body |
| `POST /api/teams/:id/invite` | `member` field of `{ status: "added", member: ... }` |
| `GET /api/teams/:id/keys/:pubkey` | Indirectly if membership is echoed (verify per-handler) |

### 9.3 Source of the Email

The team_users row stores `user_pubkey`. The user's email lives on the `users` (or equivalent account) table keyed by pubkey. Serializing `TeamUser` requires a JOIN `team_users → users` or a batched lookup in the handler.

Implementation note: where roster serialization is in a hot path (e.g. `GET /api/teams` for a user on many teams), a single JOIN at the SQL level is cheaper than N lookups in Rust.

### 9.4 Privacy and Authorization

- Callers already prove team membership to reach these endpoints; no new authorization layer is required.
- Adding `email` to this surface does **not** widen the audience: everyone who currently sees the roster already sees the pubkey. Email is the same trust scope.
- The privacy boundary is the team. Do not surface emails via any endpoint that returns team membership to non-members (if such an endpoint ever exists, it must strip `email`).

### 9.5 Rust Type Change

```rust
// Whichever module defines the serialization DTO for team membership:

#[derive(Serialize)]
pub struct TeamUserResponse {
    pub team_id: i32,
    pub user_pubkey: String,
    pub role: String,           // "Admin" | "Member"
    pub email: String,          // ← new
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

Repository method (or query builder) adjusted to fetch email alongside membership.

### 9.6 Back-compat

The field is additive. Older clients that don't know about `email` will ignore it. The current client (pre-release of this change) already tolerates the old shape; post-release it prefers `email` and falls back to the short npub label if absent.

### 9.7 Edge Cases

| Scenario | Behavior |
|---|---|
| Member account deleted but team_users row lingers | Should not happen if CASCADE is in place; if it does, serialize with empty email (or filter the row out — whichever matches existing invariants). |
| User has no email (claim-token-only account) | Serialize empty string. Client falls back to npub label. |
| Tenant isolation | Email lookup must respect the same tenant boundary as the existing `users` query — never cross tenants. |

### 9.8 Tests

- Repository/query test: roster fetch returns email populated for a normal user.
- Handler test: `GET /api/teams` response snapshot includes `email` on each `team_users` entry.
- Handler test: `POST /api/teams/:id/invite` "added" branch response includes `email` on `member`.
- Tenant isolation test: a user's email from tenant A never appears in tenant B's roster response.

## 10. Implementation Order

1. Migration: create `team_invitations` table
2. Core: `TeamInvitation` type + `TeamInvitationRepository`
3. Email: `send_team_invite_email` on `EmailSender` trait + implementations (SendGrid, SES, Dev)
4. API: `POST /teams/:id/invite` (both paths)
5. API: `GET /teams/:id/invitations`, `DELETE /teams/:id/invitations/:id`
6. API: `GET /invitations/preview`, `POST /invitations/accept`
7. Tests: unit tests for repository, integration tests for invite + accept flow
