// ABOUTME: Synvya: the team change log of an owner tenant (owner_team_events), and the member
// ABOUTME: add and remove that write it in the same transaction as the membership change
//
// Key exports: `OwnerTeamEvent`, `OwnerTeamInvitationEvent`, `OwnerTeamEventRow`,
// `record_owner_team_event`, `record_owner_team_invitation`, `add_member_logged`,
// `remove_member_logged`, `withdraw_invitation_logged`, `list_owner_team_events`.
// Neighbours: `./buyer_team.rs` (`customer_team_events`, the customer tenant's log, which this
// mirrors), `./team.rs` (the unlogged membership writes). Synvya Server reads the log through
// `GET /api/admin/owner-team-events` and writes the store part's staff records
// (account-activity.md in the Synvya docs repo). This file is Synvya-only, so an upstream merge
// does not touch it.

use crate::repositories::RepositoryError;
use crate::types::user::TeamUser;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};

/// One member change of an owner-tenant team.
#[derive(Debug, Clone)]
pub struct OwnerTeamEvent<'a> {
    pub tenant_id: i64,
    pub team_id: i32,
    /// `added`, `joined` or `removed`. An owner-tenant team has no route that changes a member's
    /// role, so the log has no `role_set`. An invitation is an `OwnerTeamInvitationEvent`.
    pub action: &'a str,
    pub member_pubkey: &'a str,
    /// The role added or joined with. On a removal the row holds the role the member had.
    pub role: Option<&'a str>,
    /// Who made the change.
    pub actor_pubkey: Option<&'a str>,
    /// A support admin's access grant or release, not a change by the team's own people.
    pub by_support: bool,
}

/// Append one member change, in the caller's transaction when it has one. The team's stored keys
/// are copied onto the row, so the log still names them after the team or a key is gone.
pub async fn record_owner_team_event<'e, E>(
    executor: E,
    event: &OwnerTeamEvent<'_>,
) -> Result<(), RepositoryError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO owner_team_events
             (tenant_id, team_id, team_key_pubkeys, action, member_pubkey, member_email, role,
              actor_pubkey, by_support)
         VALUES ($1, $2,
                 ARRAY(SELECT pubkey FROM stored_keys
                       WHERE tenant_id = $1 AND team_id = $2 ORDER BY id)::text[],
                 $3, $4, (SELECT email FROM users WHERE pubkey = $4 AND tenant_id = $1),
                 $5, $6, $7)",
    )
    .bind(event.tenant_id)
    .bind(event.team_id)
    .bind(event.action)
    .bind(event.member_pubkey)
    .bind(event.role)
    .bind(event.actor_pubkey)
    .bind(event.by_support)
    .execute(executor)
    .await?;
    Ok(())
}

/// One invitation of an owner-tenant team to an email that has no account yet. The person has no
/// key until they accept, so the entry names the email.
#[derive(Debug, Clone)]
pub struct OwnerTeamInvitationEvent<'a> {
    pub tenant_id: i64,
    pub team_id: i32,
    /// `invited` (the customer tenant's spelling) or `invitation_withdrawn`. A resend is a
    /// withdrawal and a new invitation, so it writes both.
    pub action: &'a str,
    pub email: &'a str,
    /// The role the invitation offers.
    pub role: &'a str,
    /// The admin who invited or withdrew.
    pub actor_pubkey: &'a str,
}

/// Append one invitation entry, in the caller's transaction when it has one.
pub async fn record_owner_team_invitation<'e, E>(
    executor: E,
    event: &OwnerTeamInvitationEvent<'_>,
) -> Result<(), RepositoryError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO owner_team_events
             (tenant_id, team_id, team_key_pubkeys, action, member_pubkey, member_email, role,
              actor_pubkey, by_support)
         VALUES ($1, $2,
                 ARRAY(SELECT pubkey FROM stored_keys
                       WHERE tenant_id = $1 AND team_id = $2 ORDER BY id)::text[],
                 $3, NULL, $4, $5, $6, FALSE)",
    )
    .bind(event.tenant_id)
    .bind(event.team_id)
    .bind(event.action)
    .bind(event.email)
    .bind(event.role)
    .bind(event.actor_pubkey)
    .execute(executor)
    .await?;
    Ok(())
}

/// Withdraw a pending invitation and log `invitation_withdrawn` with its email and role, in one
/// transaction. False, and no row, when no pending invitation has that id in that team.
pub async fn withdraw_invitation_logged(
    pool: &PgPool,
    tenant_id: i64,
    team_id: i32,
    invitation_id: i32,
    actor_pubkey: &str,
) -> Result<bool, RepositoryError> {
    let mut tx = pool.begin().await?;
    let withdrawn: Option<(String, String)> = sqlx::query_as(
        "UPDATE team_invitations
         SET revoked_at = NOW()
         WHERE id = $1 AND team_id = $2 AND tenant_id = $3
           AND accepted_at IS NULL
           AND revoked_at IS NULL
         RETURNING email, role",
    )
    .bind(invitation_id)
    .bind(team_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, role)) = withdrawn else {
        return Ok(false);
    };
    record_owner_team_invitation(
        &mut *tx,
        &OwnerTeamInvitationEvent {
            tenant_id,
            team_id,
            action: "invitation_withdrawn",
            email: &email,
            role: &role,
            actor_pubkey,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Add a member and log it, in one transaction. `event.role` is the role added with.
pub async fn add_member_logged(
    pool: &PgPool,
    event: &OwnerTeamEvent<'_>,
) -> Result<TeamUser, RepositoryError> {
    let mut tx = pool.begin().await?;
    let member = sqlx::query_as::<_, TeamUser>(
        "WITH ins AS (
             INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             RETURNING user_pubkey, team_id, role, created_at, updated_at
         )
         SELECT ins.user_pubkey, ins.team_id, ins.role, u.email, u.display_name, ins.created_at,
                ins.updated_at
         FROM ins
         LEFT JOIN users u ON u.pubkey = ins.user_pubkey",
    )
    .bind(event.team_id)
    .bind(event.member_pubkey)
    .bind(event.role.unwrap_or("member"))
    .fetch_one(&mut *tx)
    .await?;
    record_owner_team_event(&mut *tx, event).await?;
    tx.commit().await?;
    Ok(member)
}

/// Remove a member and log it with the role they had, in one transaction. False, and no row, when
/// they were not a member. `event.role` is ignored.
pub async fn remove_member_logged(
    pool: &PgPool,
    event: &OwnerTeamEvent<'_>,
) -> Result<bool, RepositoryError> {
    let mut tx = pool.begin().await?;
    let role: Option<String> = sqlx::query_scalar(
        "DELETE FROM team_users WHERE team_id = $1 AND user_pubkey = $2 RETURNING role",
    )
    .bind(event.team_id)
    .bind(event.member_pubkey)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(role) = role else {
        return Ok(false);
    };
    record_owner_team_event(
        &mut *tx,
        &OwnerTeamEvent {
            role: Some(&role),
            ..event.clone()
        },
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// One entry of the log, as the admin API answers it.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OwnerTeamEventRow {
    pub id: i64,
    pub team_id: i32,
    pub team_key_pubkeys: Vec<String>,
    pub action: String,
    /// Null on an invitation: the person has no key until they accept.
    pub member_pubkey: Option<String>,
    /// The invited email, or the member's when the tenant knows it.
    pub member_email: Option<String>,
    pub role: Option<String>,
    pub actor_pubkey: Option<String>,
    pub by_support: bool,
    pub created_at: DateTime<Utc>,
}

/// The log of a tenant after `after`, and from `since` when given, in id order, at most `limit`
/// entries.
pub async fn list_owner_team_events(
    pool: &PgPool,
    tenant_id: i64,
    after: i64,
    since: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<Vec<OwnerTeamEventRow>, RepositoryError> {
    sqlx::query_as(
        "SELECT id, team_id, team_key_pubkeys, action, member_pubkey, member_email, role,
                actor_pubkey, by_support, created_at
         FROM owner_team_events
         WHERE tenant_id = $1 AND id > $2 AND ($4::timestamptz IS NULL OR created_at >= $4)
         ORDER BY id LIMIT $3",
    )
    .bind(tenant_id)
    .bind(after)
    .bind(limit)
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}
