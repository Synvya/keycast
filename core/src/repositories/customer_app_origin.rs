// ABOUTME: Repository for the merchants' orders apps allowed to use the customer tenant
// ABOUTME: Read at request time, so adding a merchant needs no deploy

use super::RepositoryError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct CustomerAppOrigin {
    pub origin: String,
    pub merchant_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct CustomerAppOriginRepository {
    pool: PgPool,
}

impl CustomerAppOriginRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Allow an origin, or rename its merchant if it is already allowed.
    pub async fn add(
        &self,
        tenant_id: i64,
        origin: &str,
        merchant_name: &str,
    ) -> Result<CustomerAppOrigin, RepositoryError> {
        sqlx::query_as(
            "INSERT INTO customer_app_origins (tenant_id, origin, merchant_name)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, origin) DO UPDATE SET merchant_name = EXCLUDED.merchant_name
             RETURNING origin, merchant_name, created_at",
        )
        .bind(tenant_id)
        .bind(origin)
        .bind(merchant_name)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Stop allowing an origin. Returns whether it was allowed.
    pub async fn remove(&self, tenant_id: i64, origin: &str) -> Result<bool, RepositoryError> {
        let result =
            sqlx::query("DELETE FROM customer_app_origins WHERE tenant_id = $1 AND origin = $2")
                .bind(tenant_id)
                .bind(origin)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The merchant's name, if this origin is allowed.
    pub async fn find_merchant_name(
        &self,
        tenant_id: i64,
        origin: &str,
    ) -> Result<Option<String>, RepositoryError> {
        sqlx::query_scalar(
            "SELECT merchant_name FROM customer_app_origins WHERE tenant_id = $1 AND origin = $2",
        )
        .bind(tenant_id)
        .bind(origin)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<CustomerAppOrigin>, RepositoryError> {
        sqlx::query_as(
            "SELECT origin, merchant_name, created_at FROM customer_app_origins
             WHERE tenant_id = $1 ORDER BY origin",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}
