// ABOUTME: Repository for the apps allowed to use the customer tenant and the merchants each sells for
// ABOUTME: Read at request time, so adding an origin or a merchant needs no deploy

use super::RepositoryError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;

/// One merchant an origin sells for.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OriginMerchant {
    pub merchant_pubkey: String,
    pub merchant_name: String,
    pub created_at: DateTime<Utc>,
}

/// An approved origin and its list of merchants. A grant from this origin may name only a
/// merchant on the list.
#[derive(Debug, Clone, Serialize)]
pub struct CustomerAppOrigin {
    pub origin: String,
    /// The origin's own name, shown in the sign-in email. For a one-merchant origin it is that
    /// merchant's name.
    pub merchant_name: String,
    /// The merchant when the list has exactly one, otherwise null. Callers written before an
    /// origin could sell for several merchants read this field.
    pub merchant_pubkey: Option<String>,
    pub merchants: Vec<OriginMerchant>,
    pub created_at: DateTime<Utc>,
}

/// What removing one merchant from an origin's list did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantRemoval {
    Removed,
    /// The origin is not approved, or the merchant is not on its list.
    NotListed,
    /// The merchant is the origin's only one. Remove the origin instead.
    LastMerchant,
}

#[derive(FromRow)]
struct OriginRow {
    id: i64,
    origin: String,
    merchant_name: String,
    created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct MerchantRow {
    origin_id: i64,
    merchant_pubkey: String,
    merchant_name: String,
    created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct CustomerAppOriginRepository {
    pool: PgPool,
}

impl CustomerAppOriginRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Put a merchant on an origin's list, approving the origin first if it is new. A merchant
    /// already on the list gets the new name. The origin's own name becomes `origin_name` when
    /// given; otherwise it follows `merchant_name` while the origin has only this merchant.
    /// Authorizations already granted are not changed.
    pub async fn add_merchant(
        &self,
        tenant_id: i64,
        origin: &str,
        merchant_pubkey: &str,
        merchant_name: &str,
        origin_name: Option<&str>,
    ) -> Result<CustomerAppOrigin, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        // The no-op update returns the id of an existing row and locks it until commit
        let origin_id: i64 = sqlx::query_scalar(
            "INSERT INTO customer_app_origins (tenant_id, origin, merchant_name)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, origin) DO UPDATE SET origin = EXCLUDED.origin
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(origin)
        .bind(origin_name.unwrap_or(merchant_name))
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO customer_app_origin_merchants
                 (origin_id, tenant_id, merchant_pubkey, merchant_name)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (origin_id, merchant_pubkey) DO UPDATE
             SET merchant_name = EXCLUDED.merchant_name",
        )
        .bind(origin_id)
        .bind(tenant_id)
        .bind(merchant_pubkey)
        .bind(merchant_name)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE customer_app_origins SET merchant_name = $2
             WHERE id = $1
               AND ($3 OR (SELECT COUNT(*) FROM customer_app_origin_merchants
                           WHERE origin_id = $1) = 1)",
        )
        .bind(origin_id)
        .bind(origin_name.unwrap_or(merchant_name))
        .bind(origin_name.is_some())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        self.find(tenant_id, origin)
            .await?
            .ok_or_else(|| RepositoryError::NotFound("customer app origin".to_string()))
    }

    /// Take one merchant off an origin's list. The last merchant stays: remove the origin.
    /// Authorizations already granted for the merchant keep working until revoked.
    pub async fn remove_merchant(
        &self,
        tenant_id: i64,
        origin: &str,
        merchant_pubkey: &str,
    ) -> Result<MerchantRemoval, RepositoryError> {
        let mut tx = self.pool.begin().await?;

        // Locked so two removals cannot both see a second merchant and empty the list
        let origin_id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM customer_app_origins
             WHERE tenant_id = $1 AND origin = $2
             FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(origin)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(origin_id) = origin_id else {
            return Ok(MerchantRemoval::NotListed);
        };

        let merchants: Vec<String> = sqlx::query_scalar(
            "SELECT merchant_pubkey FROM customer_app_origin_merchants WHERE origin_id = $1",
        )
        .bind(origin_id)
        .fetch_all(&mut *tx)
        .await?;
        if !merchants.iter().any(|m| m == merchant_pubkey) {
            return Ok(MerchantRemoval::NotListed);
        }
        if merchants.len() == 1 {
            return Ok(MerchantRemoval::LastMerchant);
        }

        sqlx::query(
            "DELETE FROM customer_app_origin_merchants
             WHERE origin_id = $1 AND merchant_pubkey = $2",
        )
        .bind(origin_id)
        .bind(merchant_pubkey)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(MerchantRemoval::Removed)
    }

    /// Stop allowing an origin, with every merchant on its list. Returns whether it was allowed.
    pub async fn remove(&self, tenant_id: i64, origin: &str) -> Result<bool, RepositoryError> {
        let result =
            sqlx::query("DELETE FROM customer_app_origins WHERE tenant_id = $1 AND origin = $2")
                .bind(tenant_id)
                .bind(origin)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The origin's own name, if this origin is allowed.
    pub async fn find_name(
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

    /// The keys, in hex, of the merchants this origin sells for, or `None` if it is not allowed.
    pub async fn find_merchant_pubkeys(
        &self,
        tenant_id: i64,
        origin: &str,
    ) -> Result<Option<Vec<String>>, RepositoryError> {
        let rows: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT m.merchant_pubkey
             FROM customer_app_origins o
             LEFT JOIN customer_app_origin_merchants m ON m.origin_id = o.id
             WHERE o.tenant_id = $1 AND o.origin = $2
             ORDER BY m.created_at, m.id",
        )
        .bind(tenant_id)
        .bind(origin)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(rows.into_iter().filter_map(|(m,)| m).collect()))
    }

    /// One approved origin with its merchants.
    pub async fn find(
        &self,
        tenant_id: i64,
        origin: &str,
    ) -> Result<Option<CustomerAppOrigin>, RepositoryError> {
        Ok(self.load(tenant_id, Some(origin)).await?.into_iter().next())
    }

    /// Every approved origin with its merchants.
    pub async fn list(&self, tenant_id: i64) -> Result<Vec<CustomerAppOrigin>, RepositoryError> {
        self.load(tenant_id, None).await
    }

    async fn load(
        &self,
        tenant_id: i64,
        origin: Option<&str>,
    ) -> Result<Vec<CustomerAppOrigin>, RepositoryError> {
        let origins: Vec<OriginRow> = sqlx::query_as(
            "SELECT id, origin, merchant_name, created_at FROM customer_app_origins
             WHERE tenant_id = $1 AND ($2::TEXT IS NULL OR origin = $2)
             ORDER BY origin",
        )
        .bind(tenant_id)
        .bind(origin)
        .fetch_all(&self.pool)
        .await?;

        let ids: Vec<i64> = origins.iter().map(|o| o.id).collect();
        let merchants: Vec<MerchantRow> = sqlx::query_as(
            "SELECT origin_id, merchant_pubkey, merchant_name, created_at
             FROM customer_app_origin_merchants
             WHERE tenant_id = $1 AND origin_id = ANY($2)
             ORDER BY created_at, id",
        )
        .bind(tenant_id)
        .bind(&ids)
        .fetch_all(&self.pool)
        .await?;

        let mut by_origin: HashMap<i64, Vec<OriginMerchant>> = HashMap::new();
        for m in merchants {
            by_origin
                .entry(m.origin_id)
                .or_default()
                .push(OriginMerchant {
                    merchant_pubkey: m.merchant_pubkey,
                    merchant_name: m.merchant_name,
                    created_at: m.created_at,
                });
        }

        Ok(origins
            .into_iter()
            .map(|o| {
                let merchants = by_origin.remove(&o.id).unwrap_or_default();
                let merchant_pubkey = match merchants.as_slice() {
                    [only] => Some(only.merchant_pubkey.clone()),
                    _ => None,
                };
                CustomerAppOrigin {
                    origin: o.origin,
                    merchant_name: o.merchant_name,
                    merchant_pubkey,
                    merchants,
                    created_at: o.created_at,
                }
            })
            .collect())
    }
}
