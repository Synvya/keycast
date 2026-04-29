use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::repositories::RepositoryError;
use crate::types::team_invitation::{TeamInvitation, INVITATION_EXPIRY_DAYS};

/// Repository for team invitation database operations.
#[derive(Debug, Clone)]
pub struct TeamInvitationRepository {
    pool: PgPool,
}

impl TeamInvitationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new team invitation.
    pub async fn create(
        &self,
        team_id: i32,
        tenant_id: i64,
        email: &str,
        role: &str,
        token: &str,
        invited_by: &str,
    ) -> Result<TeamInvitation, RepositoryError> {
        let now = Utc::now();
        let expires_at = now + Duration::days(INVITATION_EXPIRY_DAYS);

        sqlx::query_as::<_, TeamInvitation>(
            "INSERT INTO team_invitations
             (team_id, tenant_id, email, role, token, invited_by, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING *",
        )
        .bind(team_id)
        .bind(tenant_id)
        .bind(email)
        .bind(role)
        .bind(token)
        .bind(invited_by)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find a valid (pending, not expired, not revoked, not accepted) invitation by token.
    pub async fn find_valid_by_token(
        &self,
        token: &str,
    ) -> Result<Option<TeamInvitation>, RepositoryError> {
        sqlx::query_as::<_, TeamInvitation>(
            "SELECT * FROM team_invitations
             WHERE token = $1
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Find any invitation by token (regardless of status).
    pub async fn find_by_token(
        &self,
        token: &str,
    ) -> Result<Option<TeamInvitation>, RepositoryError> {
        sqlx::query_as::<_, TeamInvitation>("SELECT * FROM team_invitations WHERE token = $1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// List all invitations for a team.
    pub async fn list_by_team(
        &self,
        team_id: i32,
        tenant_id: i64,
    ) -> Result<Vec<TeamInvitation>, RepositoryError> {
        sqlx::query_as::<_, TeamInvitation>(
            "SELECT * FROM team_invitations
             WHERE team_id = $1 AND tenant_id = $2
             ORDER BY created_at DESC",
        )
        .bind(team_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Check if there is already a pending invitation for this email on this team.
    pub async fn find_pending_by_email(
        &self,
        team_id: i32,
        email: &str,
    ) -> Result<Option<TeamInvitation>, RepositoryError> {
        sqlx::query_as::<_, TeamInvitation>(
            "SELECT * FROM team_invitations
             WHERE team_id = $1
               AND email = $2
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > NOW()",
        )
        .bind(team_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Mark an invitation as accepted.
    pub async fn accept(
        &self,
        token: &str,
        accepted_by: &str,
    ) -> Result<TeamInvitation, RepositoryError> {
        sqlx::query_as::<_, TeamInvitation>(
            "UPDATE team_invitations
             SET accepted_at = NOW(), accepted_by = $1
             WHERE token = $2
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > NOW()
             RETURNING *",
        )
        .bind(accepted_by)
        .bind(token)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Revoke a pending invitation (soft delete via revoked_at).
    pub async fn revoke(
        &self,
        id: i32,
        team_id: i32,
        tenant_id: i64,
    ) -> Result<(), RepositoryError> {
        let result = sqlx::query(
            "UPDATE team_invitations
             SET revoked_at = NOW()
             WHERE id = $1 AND team_id = $2 AND tenant_id = $3
               AND accepted_at IS NULL
               AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(team_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound(
                "Invitation not found or already resolved".to_string(),
            ));
        }

        Ok(())
    }
}
