use chrono::{Duration, Utc};
use sqlx::PgPool;

use crate::repositories::RepositoryError;
use crate::types::refresh_token::{hash_refresh_token, RefreshToken, REFRESH_TOKEN_EXPIRY_DAYS};

/// Repository for OAuth refresh token operations.
/// Implements token rotation per RFC 9700 - each token is one-time use.
#[derive(Debug)]
pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new refresh token (stores the hash, not the plaintext).
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database insert fails.
    pub async fn create(
        &self,
        token: &str,
        authorization_id: i32,
        tenant_id: i64,
    ) -> Result<RefreshToken, RepositoryError> {
        let token_hash = hash_refresh_token(token);
        let now = Utc::now();
        let expires_at = now + Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);

        sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth_refresh_tokens
             (token_hash, authorization_id, tenant_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *",
        )
        .bind(&token_hash)
        .bind(authorization_id)
        .bind(tenant_id)
        .bind(now)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Consume a refresh token atomically (validates + marks as consumed).
    ///
    /// Returns `None` if token is invalid, expired, or already consumed.
    /// Implements one-time use per RFC 9700 token rotation.
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database query fails.
    pub async fn consume(&self, token: &str) -> Result<Option<RefreshToken>, RepositoryError> {
        let token_hash = hash_refresh_token(token);

        let result = sqlx::query_as::<_, RefreshToken>(
            "UPDATE oauth_refresh_tokens
             SET consumed_at = NOW()
             WHERE token_hash = $1
               AND consumed_at IS NULL
               AND expires_at > NOW()
             RETURNING *",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Revoke all refresh tokens for an authorization.
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database update fails.
    pub async fn revoke_for_authorization(
        &self,
        authorization_id: i32,
    ) -> Result<u64, RepositoryError> {
        let result = sqlx::query(
            "UPDATE oauth_refresh_tokens
             SET consumed_at = NOW()
             WHERE authorization_id = $1
               AND consumed_at IS NULL",
        )
        .bind(authorization_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clean up expired and consumed tokens (for maintenance).
    ///
    /// # Errors
    ///
    /// Returns `RepositoryError` if database delete fails.
    pub async fn cleanup_old_tokens(&self, days_old: i64) -> Result<u64, RepositoryError> {
        let cutoff = Utc::now() - Duration::days(days_old);

        let result = sqlx::query(
            "DELETE FROM oauth_refresh_tokens
             WHERE (consumed_at IS NOT NULL AND consumed_at < $1)
                OR (expires_at < $1)",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_consistency() {
        let token = "test_token_12345";
        let hash1 = hash_refresh_token(token);
        let hash2 = hash_refresh_token(token);
        assert_eq!(hash1, hash2);
    }
}
