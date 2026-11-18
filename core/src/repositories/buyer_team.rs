// ABOUTME: Buyer teams in the customer tenant: the team, its own key, its members and their grants
// ABOUTME: Keeps at least one admin, and revokes a member's grants on the team key when they leave

use crate::repositories::RepositoryError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool, Postgres, Transaction};

/// The stored key name of every buyer team's key.
const TEAM_KEY_NAME: &str = "Buyer account";
/// Why a member's grants were revoked, kept on the authorization.
const REVOKED_MEMBER_LEFT: &str = "member removed from buyer team";
const REVOKED_ROLE_CHANGED: &str = "member role changed";
const REVOKED_ACCOUNT_DELETED: &str = "member account deleted";

/// A buyer team and its key.
#[derive(Debug, Clone, FromRow)]
pub struct BuyerTeam {
    pub team_id: i32,
    pub name: String,
    pub stored_key_id: i32,
    /// The team key's public key in hex: the buyer account's id.
    pub team_pubkey: String,
}

/// One member of a buyer team.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BuyerTeamMember {
    pub pubkey: String,
    pub email: Option<String>,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// One buyer team a person belongs to.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BuyerTeamMembership {
    pub team_pubkey: String,
    pub name: String,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// A grant on a team key that names its member, as the HTTP RPC loads it.
#[derive(Debug, Clone, FromRow)]
pub struct MemberGrant {
    pub id: i32,
    pub tenant_id: i64,
    pub stored_key_id: i32,
    pub member_pubkey: String,
    pub policy_id: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Whether a removal may take the last admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastAdmin {
    /// Never: a team keeps an admin. A buyer leaving or removing someone.
    Stays,
    /// Only when no other member remains, so the team is left empty with its key: a buyer
    /// account closed (Synvya Server, through the admin API).
    MayLeaveAnEmptyTeam,
}

/// The outcome of a change to a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberChange {
    /// Done. The bunker keys of the grants it revoked, for the signer and the RPC cache.
    Done { revoked_bunkers: Vec<String> },
    /// The person is not a member of the team.
    NotMember,
    /// Refused: the team would be left with no admin.
    LastAdmin,
}

/// The outcome of deleting a team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeamDeletion {
    /// Deleted. The bunker keys of grants that were still active.
    Deleted { revoked_bunkers: Vec<String> },
    /// Refused: the team still has members.
    HasMembers,
}

/// Repository for buyer teams.
#[derive(Debug, Clone)]
pub struct BuyerTeamRepository {
    pool: PgPool,
}

impl BuyerTeamRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a team and its key in one transaction, with a first admin or with no member.
    /// The first admin must already be a user.
    pub async fn create(
        &self,
        tenant_id: i64,
        name: &str,
        team_pubkey: &str,
        encrypted_secret: &[u8],
        first_admin: Option<&str>,
    ) -> Result<BuyerTeam, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let team_id: i32 = sqlx::query_scalar(
            "INSERT INTO teams (tenant_id, name, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;

        let stored_key_id: i32 = sqlx::query_scalar(
            "INSERT INTO stored_keys (tenant_id, team_id, name, pubkey, secret_key, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(team_id)
        .bind(TEAM_KEY_NAME)
        .bind(team_pubkey)
        .bind(encrypted_secret)
        .fetch_one(&mut *tx)
        .await?;

        if let Some(admin) = first_admin {
            sqlx::query(
                "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
                 VALUES ($1, $2, 'admin', NOW(), NOW())",
            )
            .bind(team_id)
            .bind(admin)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(BuyerTeam {
            team_id,
            name: name.to_string(),
            stored_key_id,
            team_pubkey: team_pubkey.to_string(),
        })
    }

    /// Find a team in the tenant by its key.
    pub async fn find_by_pubkey(
        &self,
        tenant_id: i64,
        team_pubkey: &str,
    ) -> Result<Option<BuyerTeam>, RepositoryError> {
        sqlx::query_as::<_, BuyerTeam>(
            "SELECT t.id AS team_id, t.name, sk.id AS stored_key_id, sk.pubkey AS team_pubkey
             FROM stored_keys sk
             JOIN teams t ON t.id = sk.team_id AND t.tenant_id = sk.tenant_id
             WHERE sk.tenant_id = $1 AND sk.pubkey = $2
             ORDER BY sk.id
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(team_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// The team key's encrypted secret.
    pub async fn encrypted_team_key(&self, stored_key_id: i32) -> Result<Vec<u8>, RepositoryError> {
        sqlx::query_scalar("SELECT secret_key FROM stored_keys WHERE id = $1")
            .bind(stored_key_id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// A person's role in a team, or None if they are not a member.
    pub async fn role_of(
        &self,
        team_id: i32,
        member_pubkey: &str,
    ) -> Result<Option<String>, RepositoryError> {
        sqlx::query_scalar("SELECT role FROM team_users WHERE team_id = $1 AND user_pubkey = $2")
            .bind(team_id)
            .bind(member_pubkey)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// The members of a team, admins first.
    pub async fn list_members(
        &self,
        tenant_id: i64,
        team_id: i32,
    ) -> Result<Vec<BuyerTeamMember>, RepositoryError> {
        sqlx::query_as::<_, BuyerTeamMember>(
            "SELECT tu.user_pubkey AS pubkey, u.email, tu.role, tu.created_at AS joined_at
             FROM team_users tu
             LEFT JOIN users u ON u.pubkey = tu.user_pubkey AND u.tenant_id = $2
             WHERE tu.team_id = $1
             ORDER BY CASE tu.role WHEN 'admin' THEN 0 WHEN 'orderer' THEN 1 ELSE 2 END,
                      tu.created_at",
        )
        .bind(team_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// The buyer teams a person belongs to in the tenant.
    pub async fn list_teams_of(
        &self,
        tenant_id: i64,
        member_pubkey: &str,
    ) -> Result<Vec<BuyerTeamMembership>, RepositoryError> {
        sqlx::query_as::<_, BuyerTeamMembership>(
            "SELECT DISTINCT ON (t.id)
                    sk.pubkey AS team_pubkey, t.name, tu.role, tu.created_at AS joined_at
             FROM team_users tu
             JOIN teams t ON t.id = tu.team_id
             JOIN stored_keys sk ON sk.team_id = t.id AND sk.tenant_id = t.tenant_id
             WHERE t.tenant_id = $1 AND tu.user_pubkey = $2
             ORDER BY t.id, sk.id",
        )
        .bind(tenant_id)
        .bind(member_pubkey)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Add a person to a team. Returns false, and changes nothing, if they are already a member.
    pub async fn add_member(
        &self,
        team_id: i32,
        member_pubkey: &str,
        role: &str,
    ) -> Result<bool, RepositoryError> {
        let added = sqlx::query(
            "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, $3, NOW(), NOW())
             ON CONFLICT (team_id, user_pubkey) DO NOTHING",
        )
        .bind(team_id)
        .bind(member_pubkey)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(added.rows_affected() > 0)
    }

    /// Make a person an admin of a team: add them, or raise their role. For a store invitation
    /// accepted and for the support restore.
    pub async fn make_admin(
        &self,
        team_id: i32,
        member_pubkey: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
             VALUES ($1, $2, 'admin', NOW(), NOW())
             ON CONFLICT (team_id, user_pubkey) DO UPDATE SET role = 'admin', updated_at = NOW()",
        )
        .bind(team_id)
        .bind(member_pubkey)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Change a member's role. Refuses to leave the team with no admin. A member made a viewer
    /// loses their grants on the team key, since a viewer places no order.
    pub async fn change_role(
        &self,
        team: &BuyerTeam,
        member_pubkey: &str,
        role: &str,
    ) -> Result<MemberChange, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let Some(current) = lock_and_read_role(&mut tx, team.team_id, member_pubkey).await? else {
            return Ok(MemberChange::NotMember);
        };
        if current == "admin"
            && role != "admin"
            && other_admins(&mut tx, team.team_id, member_pubkey).await? == 0
        {
            return Ok(MemberChange::LastAdmin);
        }

        sqlx::query(
            "UPDATE team_users SET role = $3, updated_at = NOW()
             WHERE team_id = $1 AND user_pubkey = $2",
        )
        .bind(team.team_id)
        .bind(member_pubkey)
        .bind(role)
        .execute(&mut *tx)
        .await?;

        let revoked_bunkers = if role == "viewer" && current != "viewer" {
            revoke_member_grants(
                &mut tx,
                team.stored_key_id,
                member_pubkey,
                REVOKED_ROLE_CHANGED,
            )
            .await?
        } else {
            Vec::new()
        };

        tx.commit().await?;
        Ok(MemberChange::Done { revoked_bunkers })
    }

    /// Remove a member and revoke their grants on the team key. Refuses to remove the last admin.
    pub async fn remove_member(
        &self,
        team: &BuyerTeam,
        member_pubkey: &str,
        last_admin: LastAdmin,
    ) -> Result<MemberChange, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let Some(current) = lock_and_read_role(&mut tx, team.team_id, member_pubkey).await? else {
            return Ok(MemberChange::NotMember);
        };
        if current == "admin" && other_admins(&mut tx, team.team_id, member_pubkey).await? == 0 {
            let refuse = match last_admin {
                LastAdmin::Stays => true,
                // Only when the team would be left with members and no admin
                LastAdmin::MayLeaveAnEmptyTeam => {
                    other_members(&mut tx, team.team_id, member_pubkey).await? > 0
                }
            };
            if refuse {
                return Ok(MemberChange::LastAdmin);
            }
        }

        sqlx::query("DELETE FROM team_users WHERE team_id = $1 AND user_pubkey = $2")
            .bind(team.team_id)
            .bind(member_pubkey)
            .execute(&mut *tx)
            .await?;
        let revoked_bunkers = revoke_member_grants(
            &mut tx,
            team.stored_key_id,
            member_pubkey,
            REVOKED_MEMBER_LEFT,
        )
        .await?;

        tx.commit().await?;
        Ok(MemberChange::Done { revoked_bunkers })
    }

    /// Delete a team that has no member, with its key, grants, policies and invitations.
    pub async fn delete_if_empty(
        &self,
        tenant_id: i64,
        team: &BuyerTeam,
    ) -> Result<TeamDeletion, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM teams WHERE id = $1 FOR UPDATE")
            .bind(team.team_id)
            .execute(&mut *tx)
            .await?;

        let members: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_users WHERE team_id = $1")
            .bind(team.team_id)
            .fetch_one(&mut *tx)
            .await?;
        if members > 0 {
            return Ok(TeamDeletion::HasMembers);
        }

        let revoked_bunkers: Vec<String> = sqlx::query_scalar(
            "DELETE FROM authorizations
             WHERE tenant_id = $1
               AND stored_key_id IN (SELECT id FROM stored_keys WHERE team_id = $2)
             RETURNING bunker_public_key",
        )
        .bind(tenant_id)
        .bind(team.team_id)
        .fetch_all(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM stored_keys WHERE tenant_id = $1 AND team_id = $2")
            .bind(tenant_id)
            .bind(team.team_id)
            .execute(&mut *tx)
            .await?;

        // A buyer team's policies each own their permission
        let permission_ids: Vec<i32> = sqlx::query_scalar(
            "DELETE FROM policy_permissions
             WHERE policy_id IN (SELECT id FROM policies WHERE team_id = $1)
             RETURNING permission_id",
        )
        .bind(team.team_id)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM permissions WHERE id = ANY($1)")
            .bind(&permission_ids)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM policies WHERE team_id = $1")
            .bind(team.team_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM team_invitations WHERE team_id = $1")
            .bind(team.team_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM teams WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(team.team_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(TeamDeletion::Deleted { revoked_bunkers })
    }

    /// The policy of a member's commerce grant on the team key: `commerce_envelope` for one
    /// merchant, bound to the member by `sent_by`. Created on first use.
    pub async fn find_or_create_member_commerce_policy(
        &self,
        team_id: i32,
        merchant_pubkey: &str,
        member_pubkey: &str,
    ) -> Result<i32, RepositoryError> {
        self.find_or_create_team_policy(
            team_id,
            &format!("commerce_envelope:{merchant_pubkey}:{member_pubkey}"),
            "commerce_envelope",
            serde_json::json!({ "merchant_pubkey": merchant_pubkey, "sent_by": member_pubkey }),
        )
        .await
    }

    /// The policy of a viewer's read grant on the team key: `decrypt_only`. Created on first use.
    pub async fn find_or_create_read_policy(&self, team_id: i32) -> Result<i32, RepositoryError> {
        self.find_or_create_team_policy(
            team_id,
            "decrypt_only",
            "decrypt_only",
            serde_json::json!({}),
        )
        .await
    }

    async fn find_or_create_team_policy(
        &self,
        team_id: i32,
        name: &str,
        identifier: &str,
        config: serde_json::Value,
    ) -> Result<i32, RepositoryError> {
        let existing: Option<i32> = sqlx::query_scalar(
            "SELECT id FROM policies WHERE team_id = $1 AND name = $2 ORDER BY id LIMIT 1",
        )
        .bind(team_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(policy_id) = existing {
            return Ok(policy_id);
        }

        let mut tx = self.pool.begin().await?;
        let policy_id: i32 = sqlx::query_scalar(
            "INSERT INTO policies (name, team_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id",
        )
        .bind(name)
        .bind(team_id)
        .fetch_one(&mut *tx)
        .await?;
        let permission_id: i32 = sqlx::query_scalar(
            "INSERT INTO permissions (identifier, config, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())
             RETURNING id",
        )
        .bind(identifier)
        .bind(config)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
             VALUES ($1, $2, NOW(), NOW())",
        )
        .bind(policy_id)
        .bind(permission_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(policy_id)
    }

    /// Record a grant on the team key that names its member.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_member_grant(
        &self,
        tenant_id: i64,
        stored_key_id: i32,
        policy_id: i32,
        secret_hash: &str,
        bunker_pubkey: &str,
        relays: &serde_json::Value,
        member_pubkey: &str,
        label: &str,
    ) -> Result<i32, RepositoryError> {
        sqlx::query_scalar(
            "INSERT INTO authorizations
                 (tenant_id, stored_key_id, policy_id, secret_hash, bunker_public_key, relays,
                  member_pubkey, label, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(stored_key_id)
        .bind(policy_id)
        .bind(secret_hash)
        .bind(bunker_pubkey)
        .bind(relays)
        .bind(member_pubkey)
        .bind(label)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// The member grant with this bunker key, revoked or not.
    pub async fn find_member_grant(
        &self,
        bunker_pubkey: &str,
    ) -> Result<Option<MemberGrant>, RepositoryError> {
        sqlx::query_as::<_, MemberGrant>(
            "SELECT id, tenant_id, stored_key_id, member_pubkey, policy_id, expires_at, revoked_at
             FROM authorizations
             WHERE bunker_public_key = $1 AND member_pubkey IS NOT NULL
             ORDER BY id DESC
             LIMIT 1",
        )
        .bind(bunker_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }
}

/// Lock the team row, so two changes cannot each remove a different last admin, and read the
/// member's role.
async fn lock_and_read_role(
    tx: &mut Transaction<'_, Postgres>,
    team_id: i32,
    member_pubkey: &str,
) -> Result<Option<String>, RepositoryError> {
    sqlx::query("SELECT id FROM teams WHERE id = $1 FOR UPDATE")
        .bind(team_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query_scalar("SELECT role FROM team_users WHERE team_id = $1 AND user_pubkey = $2")
        .bind(team_id)
        .bind(member_pubkey)
        .fetch_optional(&mut **tx)
        .await
        .map_err(Into::into)
}

async fn other_admins(
    tx: &mut Transaction<'_, Postgres>,
    team_id: i32,
    member_pubkey: &str,
) -> Result<i64, RepositoryError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM team_users
         WHERE team_id = $1 AND user_pubkey != $2 AND role = 'admin'",
    )
    .bind(team_id)
    .bind(member_pubkey)
    .fetch_one(&mut **tx)
    .await
    .map_err(Into::into)
}

async fn other_members(
    tx: &mut Transaction<'_, Postgres>,
    team_id: i32,
    member_pubkey: &str,
) -> Result<i64, RepositoryError> {
    sqlx::query_scalar("SELECT COUNT(*) FROM team_users WHERE team_id = $1 AND user_pubkey != $2")
        .bind(team_id)
        .bind(member_pubkey)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
}

async fn revoke_member_grants(
    tx: &mut Transaction<'_, Postgres>,
    stored_key_id: i32,
    member_pubkey: &str,
    reason: &str,
) -> Result<Vec<String>, RepositoryError> {
    sqlx::query_scalar(
        "UPDATE authorizations
         SET revoked_at = NOW(), revoked_reason = $3, updated_at = NOW()
         WHERE stored_key_id = $1 AND member_pubkey = $2 AND revoked_at IS NULL
         RETURNING bunker_public_key",
    )
    .bind(stored_key_id)
    .bind(member_pubkey)
    .bind(reason)
    .fetch_all(&mut **tx)
    .await
    .map_err(Into::into)
}

/// Revoke every grant that names this person on any team key, when their account is deleted.
/// Returns the bunker keys revoked.
pub async fn revoke_grants_of_deleted_member(
    tx: &mut Transaction<'_, Postgres>,
    member_pubkey: &str,
) -> Result<Vec<String>, RepositoryError> {
    sqlx::query_scalar(
        "UPDATE authorizations
         SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
         WHERE member_pubkey = $1 AND revoked_at IS NULL
         RETURNING bunker_public_key",
    )
    .bind(member_pubkey)
    .bind(REVOKED_ACCOUNT_DELETED)
    .fetch_all(&mut **tx)
    .await
    .map_err(Into::into)
}

/// Record one signature or encryption made under a grant. Does nothing unless the grant names a
/// member, so restaurant staff and support grants write nothing.
pub async fn record_team_signing(
    pool: &PgPool,
    authorization_id: i64,
    method: &str,
    event_kind: Option<i32>,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO team_signing_activity
             (tenant_id, authorization_id, stored_key_id, member_pubkey, method, event_kind)
         SELECT tenant_id, id, stored_key_id, member_pubkey, $2, $3
         FROM authorizations
         WHERE id = $1 AND member_pubkey IS NOT NULL",
    )
    .bind(authorization_id as i32)
    .bind(method)
    .bind(event_kind)
    .execute(pool)
    .await?;
    Ok(())
}

/// The kind of the event in an encryption's plaintext, if it is an event.
pub fn plaintext_event_kind(plaintext: &str) -> Option<i32> {
    serde_json::from_str::<serde_json::Value>(plaintext)
        .ok()?
        .get("kind")?
        .as_i64()
        .map(|kind| kind as i32)
}
