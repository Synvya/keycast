//! Synvya: the read of an owner tenant's team change log.
//!
//! `GET /api/admin/owner-team-events?after=&since=&limit=` answers
//! `{ events, next_after }` for the tenant of the request's host, in id order,
//! as `GET /api/admin/customer-team-events` does for the customer tenant. Each
//! event names the team, the team's stored keys when the change was made, the
//! action (`added`, `joined`, `removed`), the member, the role, who made the
//! change and whether a support admin's access grant made it. Synvya Server
//! reads it on a sweep and writes a store-part record for each key that is a
//! store (account-activity.md in the Synvya docs repo).
//!
//! Support admins and full admins only, as the customer-team log. This file is
//! Synvya-only, so an upstream merge does not touch it.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admin::is_support_admin;
use super::routes::AuthState;
use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use crate::api::tenant::TenantExtractor;
use keycast_core::repositories::{list_owner_team_events, OwnerTeamEventRow};

/// The most entries one read answers.
const EVENTS_MAX: i64 = 500;
const EVENTS_DEFAULT: i64 = 100;

#[derive(Debug, Deserialize)]
pub struct OwnerTeamEventsQuery {
    pub after: Option<i64>,
    /// ISO 8601. Used only when `after` is absent or 0: the first read from a point in time.
    pub since: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct OwnerTeamEventsResponse {
    pub events: Vec<OwnerTeamEventRow>,
    /// The last id answered, or `after` when nothing is newer: the next read's `after`.
    pub next_after: i64,
}

/// GET /api/admin/owner-team-events
pub async fn list_events(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Query(query): Query<OwnerTeamEventsQuery>,
) -> ApiResult<Json<OwnerTeamEventsResponse>> {
    if !is_support_admin(&auth).await {
        return Err(ApiError::forbidden("Admin access required"));
    }
    let after = query.after.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(EVENTS_DEFAULT).clamp(1, EVENTS_MAX);
    let since = match (after, query.since.as_deref()) {
        (0, Some(value)) => Some(
            DateTime::parse_from_rfc3339(value)
                .map_err(|_| ApiError::bad_request("since must be an ISO 8601 time"))?
                .with_timezone(&Utc),
        ),
        _ => None,
    };
    let events =
        list_owner_team_events(&auth_state.state.db, tenant.0.id, after, since, limit).await?;
    let next_after = events.last().map_or(after, |e| e.id);
    Ok(Json(OwnerTeamEventsResponse { events, next_after }))
}
