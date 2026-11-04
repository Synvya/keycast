// ABOUTME: Repository for email sign-in link tokens
// ABOUTME: Stores only the token's hash; a token can be consumed once, even under concurrent clicks

use super::RepositoryError;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use std::net::IpAddr;

/// What a sign-in link is for.
pub const PURPOSE_SIGN_IN: &str = "sign_in";
pub const PURPOSE_DELETE_ACCOUNT: &str = "delete_account";

/// A token that was just consumed.
#[derive(Debug, Clone, FromRow)]
pub struct ConsumedMagicLink {
    pub email: String,
    pub purpose: String,
    pub app_origin: String,
}

/// The value stored for a token: sha256, hex.
pub fn hash_magic_link_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Clone)]
pub struct MagicLinkTokenRepository {
    pool: PgPool,
}

impl MagicLinkTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Store a new token. The plain token is hashed here and never written.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: i64,
        email: &str,
        token: &str,
        purpose: &str,
        app_origin: &str,
        expires_at: DateTime<Utc>,
        request_ip: Option<IpAddr>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO magic_link_tokens
             (tenant_id, email, token_hash, purpose, app_origin, expires_at, request_ip)
             VALUES ($1, $2, $3, $4, $5, $6, ($7::text)::inet)",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(hash_magic_link_token(token))
        .bind(purpose)
        .bind(app_origin)
        .bind(expires_at)
        .bind(request_ip.map(|ip| ip.to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consume a token. Returns None if it is unknown, used, expired or from another tenant.
    /// One UPDATE, so a token can be consumed once even under concurrent clicks.
    pub async fn consume(
        &self,
        token: &str,
        tenant_id: i64,
    ) -> Result<Option<ConsumedMagicLink>, RepositoryError> {
        sqlx::query_as(
            "UPDATE magic_link_tokens
             SET consumed_at = NOW()
             WHERE token_hash = $1 AND tenant_id = $2
               AND consumed_at IS NULL AND expires_at > NOW()
             RETURNING email, purpose, app_origin",
        )
        .bind(hash_magic_link_token(token))
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// How many links this email has been sent since a point in time.
    pub async fn count_recent(
        &self,
        tenant_id: i64,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<i64, RepositoryError> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM magic_link_tokens
             WHERE tenant_id = $1 AND email = $2 AND created_at >= $3",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Remove tokens older than a day. Returns how many were removed.
    pub async fn purge_expired(&self) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "DELETE FROM magic_link_tokens WHERE created_at < NOW() - INTERVAL '1 day'",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
