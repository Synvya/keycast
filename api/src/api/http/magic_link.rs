// ABOUTME: Email-link sign-in for customer accounts, which have no password
// ABOUTME: Requesting a link never creates an account and answers the same for any email

use super::auth::{app_url_is_allowed, generate_secure_token, AuthError};
use super::routes::AuthState;
use crate::api::tenant::TenantExtractor;
use crate::email_service::{EmailSender, EmailService};
use crate::rate_limit;
use crate::redis::PrefixedRedis;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use keycast_core::repositories::{MagicLinkTokenRepository, PURPOSE_SIGN_IN};
use nostr_sdk::Url;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::IpAddr;

/// How long a link works.
const MAGIC_LINK_EXPIRY_MINUTES: i64 = 15;
/// At most one link per email in this many seconds.
const EMAIL_WINDOW_SECONDS: u64 = 60;
/// At most this many links per email per hour.
const EMAIL_HOURLY_LIMIT: i64 = 5;
/// At most this many requests per IP per hour.
const IP_HOURLY_LIMIT: u64 = 20;
const HOUR_SECONDS: u64 = 3600;
/// The longest address the email column holds.
const MAX_EMAIL_LENGTH: usize = 255;

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
    pub app_url: String,
}

#[derive(Debug, Serialize)]
pub struct MagicLinkResponse {
    pub success: bool,
}

/// Trim and lowercase an address, or None if it is malformed.
pub fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;

    let well_formed = email.len() <= MAX_EMAIL_LENGTH
        && !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());

    well_formed.then_some(email)
}

/// Parse the page a link should land on, if its origin is allowed.
pub fn parse_app_url(app_url: &str) -> Option<Url> {
    let url = Url::parse(app_url.trim()).ok()?;
    let is_web = matches!(url.scheme(), "http" | "https");
    let has_no_credentials = url.username().is_empty() && url.password().is_none();

    (is_web && has_no_credentials && app_url_is_allowed(&url.origin().ascii_serialization()))
        .then_some(url)
}

/// The name a customer knows the merchant by, from the hostname of its orders app.
/// It comes from the allowed origin, never from the request, so a caller cannot put
/// arbitrary text in the email.
pub fn merchant_name(app_url: &Url) -> String {
    let host = app_url.host_str().unwrap_or_default();
    host.strip_prefix("orders.").unwrap_or(host).to_string()
}

/// The link to send: the app's page with the token added to its query string.
pub fn magic_link(app_url: &Url, token: &str) -> String {
    let mut link = app_url.clone();
    link.set_fragment(None);
    link.query_pairs_mut().append_pair("token", token);
    link.to_string()
}

/// Apply the limits, store the token and send the email. Returns whether a link was sent.
///
/// Throttled requests send nothing and are only logged: the caller's answer never changes.
pub async fn send_sign_in_link(
    pool: &PgPool,
    redis: Option<&PrefixedRedis>,
    email_sender: &dyn EmailSender,
    tenant_id: i64,
    email: &str,
    app_url: &Url,
    request_ip: Option<IpAddr>,
) -> bool {
    if let Some(ip) = request_ip {
        let key = format!("magic_link:ip:{tenant_id}:{ip}");
        if !rate_limit::under_limit(redis, &key, IP_HOURLY_LIMIT, HOUR_SECONDS).await {
            tracing::warn!("Sign-in link throttled: too many requests from one IP");
            return false;
        }
    }

    let repo = MagicLinkTokenRepository::new(pool.clone());
    let an_hour_ago = Utc::now() - Duration::hours(1);
    match repo.count_recent(tenant_id, email, an_hour_ago).await {
        Ok(count) if count >= EMAIL_HOURLY_LIMIT => {
            tracing::warn!("Sign-in link throttled: hourly limit for one email");
            return false;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("Failed to count sign-in links: {}", e);
            return false;
        }
    }

    let key = format!(
        "magic_link:email:{tenant_id}:{}",
        rate_limit::email_key(email)
    );
    if !rate_limit::once_per_window(redis, &key, EMAIL_WINDOW_SECONDS).await {
        tracing::warn!("Sign-in link throttled: one link per email per minute");
        return false;
    }

    let token = generate_secure_token();
    let expires_at = Utc::now() + Duration::minutes(MAGIC_LINK_EXPIRY_MINUTES);
    if let Err(e) = repo
        .create(
            tenant_id,
            email,
            &token,
            PURPOSE_SIGN_IN,
            app_url.as_str(),
            expires_at,
            request_ip,
        )
        .await
    {
        tracing::error!("Failed to store sign-in link: {}", e);
        return false;
    }

    let link = magic_link(app_url, &token);
    if let Err(e) = email_sender
        .send_magic_link_email(email, &link, &merchant_name(app_url))
        .await
    {
        tracing::error!("Failed to send sign-in link: {}", e);
        return false;
    }

    true
}

/// POST /api/auth/magic-link - email a sign-in link.
///
/// Only the customer tenant has email-link sign-in: elsewhere this would let a restaurant
/// owner in without their password. Everything after validation runs in a spawned task, so
/// neither the answer nor its timing depends on the email or on being throttled.
pub async fn request_magic_link(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> Result<Response, AuthError> {
    if !tenant.0.is_customer_tenant() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let email = normalize_email(&req.email)
        .ok_or_else(|| AuthError::BadRequest("Invalid email address".to_string()))?;
    let app_url = parse_app_url(&req.app_url)
        .ok_or_else(|| AuthError::BadRequest("app_url is not allowed".to_string()))?;

    let tenant_id = tenant.0.id;
    let request_ip = rate_limit::client_ip(&headers);
    let state = auth_state.state.clone();

    tokio::spawn(async move {
        let email_service = match EmailService::new().await {
            Ok(email_service) => email_service,
            Err(e) => {
                tracing::error!("Failed to create email service: {}", e);
                return;
            }
        };
        send_sign_in_link(
            &state.db,
            state.redis.as_ref(),
            email_service.sender(),
            tenant_id,
            &email,
            &app_url,
            request_ip,
        )
        .await;
    });

    Ok(Json(MagicLinkResponse { success: true }).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_email() {
        assert_eq!(
            normalize_email("  Dana@Example.COM "),
            Some("dana@example.com".to_string())
        );
        for bad in [
            "",
            "dana",
            "@example.com",
            "dana@",
            "dana@example",
            "dana@.example.com",
            "dana@example.com.",
            "a@b@example.com",
            "da na@example.com",
            "dana@example.com\r\nBcc: x@example.com",
        ] {
            assert_eq!(normalize_email(bad), None, "{bad:?}");
        }
        assert_eq!(
            normalize_email(&format!("{}@example.com", "a".repeat(256))),
            None
        );
    }

    #[test]
    fn test_merchant_name_comes_from_the_hostname() {
        let url = Url::parse("https://orders.example.com/signin").unwrap();
        assert_eq!(merchant_name(&url), "example.com");
        let url = Url::parse("https://shop.example.com/signin").unwrap();
        assert_eq!(merchant_name(&url), "shop.example.com");
    }

    #[test]
    fn test_magic_link_appends_the_token() {
        let url = Url::parse("https://orders.example.com/signin").unwrap();
        assert_eq!(
            magic_link(&url, "abc"),
            "https://orders.example.com/signin?token=abc"
        );

        let url = Url::parse("https://orders.example.com/signin?next=cart#top").unwrap();
        assert_eq!(
            magic_link(&url, "abc"),
            "https://orders.example.com/signin?next=cart&token=abc"
        );
    }
}
