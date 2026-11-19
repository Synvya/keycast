// ABOUTME: Fresh confirmations for the buyer team routes that change members or roles (BSP-14)
// ABOUTME: A 428 with an emailed link, the confirm route, and the check of the request sent again

//! Synvya. Store API contract §14.2, §14.3 and §14.5 in the Synvya docs repo.
//!
//! A route that needs a confirmation calls [`require_confirmation`] once its caller is known to
//! be allowed to make the change. Without a usable confirmation it answers 428
//! `confirmation_required` and emails the acting member a link. The member opens the link in the
//! buyer app, which calls [`confirm`] with the member's session, then sends the same request again
//! with `X-Synvya-Confirmation: <confirmation_id>`. The confirmation is bound to the method, path
//! and body of that one request, expires 10 minutes after it is made, and is used once.

use super::auth::app_url_is_allowed;
use super::routes::AuthState;
use crate::api::error::{ApiError, ApiResult};
use crate::api::tenant::TenantExtractor;
use crate::email_service::EmailService;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use keycast_core::repositories::UserRepository;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// The header that carries a confirmation id on the request sent again.
pub const CONFIRMATION_HEADER: &str = "x-synvya-confirmation";
/// How long a confirmation lasts, from the 428 to the request sent again.
const LIFETIME_MINUTES: i64 = 10;
/// The longest confirmation id or token looked up; anything longer is not one.
const MAX_ID_LENGTH: usize = 128;

/// A change that needs a confirmation: who asks, what it is, and the request it is bound to.
pub struct ConfirmedChange<'a> {
    pub tenant_id: i64,
    pub member_pubkey: &'a str,
    /// The stored action name, such as `team_invite`.
    pub action: &'static str,
    /// The change in a few words for the email, such as "invite a team member".
    pub what: &'static str,
    pub method: &'a str,
    /// The path without its query.
    pub path: &'a str,
    pub body: &'a [u8],
}

/// SHA-256 of `METHOD \n path \n body`, in hex: what binds a confirmation to one request.
pub fn request_digest(method: &str, path: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(method.to_uppercase().as_bytes());
    hasher.update(b"\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// SHA-256 of a link token, in hex. The table keeps only this.
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buffer);
    hex::encode(buffer)
}

fn error_body(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": message, "code": code }))).into_response()
}

/// The origin the link opens on: the request's `Origin` when Keycast allows it, otherwise the
/// first entry of `ALLOWED_ORIGINS`.
fn link_origin(headers: &HeaderMap) -> Option<String> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if app_url_is_allowed(origin) {
            return Some(origin.trim_end_matches('/').to_string());
        }
    }
    std::env::var("ALLOWED_ORIGINS").ok().and_then(|list| {
        list.split(',')
            .map(|entry| entry.trim().trim_end_matches('/'))
            .find(|entry| !entry.is_empty())
            .map(str::to_string)
    })
}

/// `None` when the request carries a confirmation for exactly this change, which is now spent.
/// Otherwise a new confirmation is made, its link is emailed, and the 428 to send back is
/// returned.
pub async fn require_confirmation(
    pool: &PgPool,
    headers: &HeaderMap,
    change: &ConfirmedChange<'_>,
) -> ApiResult<Option<Response>> {
    let digest = request_digest(change.method, change.path, change.body);

    if let Some(id) = headers
        .get(CONFIRMATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|id| !id.is_empty() && id.len() <= MAX_ID_LENGTH)
    {
        // Spend it only if it is confirmed, unspent, unexpired, this member's and this request's.
        let spent: Option<String> = sqlx::query_scalar(
            "UPDATE fresh_confirmations SET spent_at = NOW()
             WHERE id = $1 AND tenant_id = $2 AND member_pubkey = $3 AND digest = $4
               AND confirmed_at IS NOT NULL AND spent_at IS NULL AND expires_at > NOW()
             RETURNING id",
        )
        .bind(id)
        .bind(change.tenant_id)
        .bind(change.member_pubkey)
        .bind(&digest)
        .fetch_optional(pool)
        .await?;
        if spent.is_some() {
            return Ok(None);
        }
    }

    let id = random_hex(16);
    let token = random_hex(32);
    let expires_at = Utc::now() + Duration::minutes(LIFETIME_MINUTES);
    sqlx::query(
        "INSERT INTO fresh_confirmations
           (id, tenant_id, member_pubkey, action, digest, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(change.tenant_id)
    .bind(change.member_pubkey)
    .bind(change.action)
    .bind(&digest)
    .bind(token_hash(&token))
    .bind(expires_at)
    .execute(pool)
    .await?;

    send_link(pool, headers, change, &token).await;
    tracing::info!(
        event = "fresh_confirmation_required",
        tenant_id = change.tenant_id,
        action = change.action,
        confirmation_id = %id,
        "Fresh confirmation required"
    );

    Ok(Some(
        (
            StatusCode::PRECONDITION_REQUIRED,
            Json(json!({
                "error": "Confirm this change from the link sent to your email",
                "code": "confirmation_required",
                "confirmation_id": id,
                "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            })),
        )
            .into_response(),
    ))
}

/// Email the link to the acting member, in the background. A failure is logged: the member can
/// send the request again for a new link.
async fn send_link(pool: &PgPool, headers: &HeaderMap, change: &ConfirmedChange<'_>, token: &str) {
    let Some(origin) = link_origin(headers) else {
        tracing::error!("Fresh confirmation: no allowed origin to build the link on");
        return;
    };
    let email = match UserRepository::new(pool.clone())
        .get_email(change.member_pubkey, change.tenant_id)
        .await
    {
        Ok(email) => email,
        Err(e) => {
            tracing::warn!(
                "Fresh confirmation: the member has no email to send to: {}",
                e
            );
            return;
        }
    };
    let link = format!("{origin}/confirm/keycast/{token}");
    let what = change.what;
    tokio::spawn(async move {
        match EmailService::new().await {
            Ok(service) => {
                if let Err(e) = service
                    .sender()
                    .send_confirmation_email(&email, &link, what)
                    .await
                {
                    tracing::error!("Fresh confirmation email failed: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to create email service: {}", e),
        }
    });
}

/// POST /api/customer/confirmations/{token} - the member who asked for a change confirms it with
/// their own session. Another member's session, no session and an unknown token are all 404, so
/// a token proves nothing to anyone else. A used or expired token is 410.
pub async fn confirm(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let not_found = || error_body(StatusCode::NOT_FOUND, "not_found", "Confirmation not found");
    let expired = || {
        error_body(
            StatusCode::GONE,
            "confirmation_expired",
            "This confirmation was used or has expired",
        )
    };

    let session = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok());
    let Some(session) = session else {
        return Ok(not_found());
    };
    let Ok((pubkey, _, _, _)) = crate::ucan_auth::validate_ucan_token(session, tenant_id).await
    else {
        return Ok(not_found());
    };
    if token.is_empty() || token.len() > MAX_ID_LENGTH {
        return Ok(not_found());
    }

    type Row = (String, String, String, DateTime<Utc>, Option<DateTime<Utc>>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, member_pubkey, action, expires_at, confirmed_at
         FROM fresh_confirmations WHERE token_hash = $1 AND tenant_id = $2",
    )
    .bind(token_hash(&token))
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    let Some((id, member, action, expires_at, confirmed_at)) = row else {
        return Ok(not_found());
    };
    if member.trim() != pubkey {
        return Ok(not_found());
    }
    if confirmed_at.is_some() || expires_at <= Utc::now() {
        return Ok(expired());
    }

    let confirmed: Option<DateTime<Utc>> = sqlx::query_scalar(
        "UPDATE fresh_confirmations SET confirmed_at = NOW()
         WHERE id = $1 AND confirmed_at IS NULL AND expires_at > NOW()
         RETURNING confirmed_at",
    )
    .bind(&id)
    .fetch_optional(pool)
    .await?;
    let Some(confirmed_at) = confirmed else {
        return Ok(expired());
    };

    Ok(Json(json!({
        "confirmation_id": id,
        "action": action,
        "confirmed_at": confirmed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
    .into_response())
}

/// Shorthand for the routes: the request's body parsed as JSON, or a 400.
pub fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("Invalid body: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_binds_method_path_and_body() {
        let base = request_digest("POST", "/api/customer/teams/role", b"{\"role\":\"viewer\"}");
        assert_eq!(base.len(), 64);
        assert_eq!(
            base,
            request_digest("post", "/api/customer/teams/role", b"{\"role\":\"viewer\"}")
        );
        assert_ne!(
            base,
            request_digest(
                "POST",
                "/api/customer/teams/remove",
                b"{\"role\":\"viewer\"}"
            )
        );
        assert_ne!(
            base,
            request_digest("POST", "/api/customer/teams/role", b"{\"role\":\"admin\"}")
        );
    }

    #[test]
    fn a_token_is_kept_as_its_sha256() {
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
