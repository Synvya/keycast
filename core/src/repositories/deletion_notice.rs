// ABOUTME: Repository for notices telling Synvya Server a customer account was deleted
// ABOUTME: Notices are written with the deletion and removed once acknowledged

use super::RepositoryError;
use chrono::{DateTime, Duration, Utc};
use sqlx::{FromRow, PgPool};

/// The longest wait between attempts.
const MAX_RETRY_DELAY_MINUTES: i64 = 60;

#[derive(Debug, Clone, FromRow)]
pub struct DeletionNotice {
    pub id: i64,
    pub pubkey: String,
    pub deleted_at: DateTime<Utc>,
    pub attempts: i32,
}

#[derive(Clone)]
pub struct DeletionNoticeRepository {
    pool: PgPool,
}

impl DeletionNoticeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Notices due for delivery, oldest first.
    pub async fn find_due(&self, limit: i64) -> Result<Vec<DeletionNotice>, RepositoryError> {
        sqlx::query_as(
            "SELECT id, pubkey, deleted_at, attempts FROM customer_deletion_notices
             WHERE next_attempt_at <= NOW()
             ORDER BY deleted_at
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// The server acknowledged this notice, so it is done.
    pub async fn acknowledge(&self, id: i64) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM customer_deletion_notices WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delivery failed: try again later, waiting longer each time up to an hour.
    pub async fn schedule_retry(&self, notice: &DeletionNotice) -> Result<(), RepositoryError> {
        let delay = 2_i64
            .saturating_pow(notice.attempts.clamp(0, 16) as u32)
            .min(MAX_RETRY_DELAY_MINUTES);
        sqlx::query(
            "UPDATE customer_deletion_notices
             SET attempts = attempts + 1, next_attempt_at = $1
             WHERE id = $2",
        )
        .bind(Utc::now() + Duration::minutes(delay))
        .bind(notice.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
