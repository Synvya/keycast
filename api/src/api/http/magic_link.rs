// ABOUTME: Email-link sign-in for customer accounts, which have no password
// ABOUTME: Requesting a link never creates an account and answers the same for any email

use super::auth::{
    app_url_is_allowed, generate_secure_token, generate_server_signed_ucan, token_expiry_seconds,
    AuthError,
};
use super::oauth::{create_oauth_authorization, CreateAuthorizationParams};
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
use keycast_core::repositories::{
    MagicLinkTokenRepository, PolicyRepository, RepositoryError, UserRepository, PURPOSE_SIGN_IN,
};
use nostr_sdk::{Keys, PublicKey, SecretKey, Url};
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
/// The only scope email-link sign-in can grant.
const COMMERCE_SCOPE: &str = "policy:commerce_envelope";
/// One answer for an unknown, used, expired or other-tenant token.
const INVALID_LINK: &str = "invalid_or_expired_link";

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

#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkRequest {
    pub token: String,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub merchant_pubkey: Option<String>,
    /// A secret key from the browser, stored as the key of a new account.
    pub local_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifiedAuthorization {
    pub bunker_url: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyMagicLinkResponse {
    pub success: bool,
    pub session_token: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<VerifiedAuthorization>,
}

/// What the app asked to be allowed to do for the customer.
struct CommerceGrant {
    client_id: String,
    redirect_uri: String,
    merchant_pubkey: PublicKey,
}

/// Read the grant from the request. The four fields come together or not at all.
fn parse_commerce_grant(req: &VerifyMagicLinkRequest) -> Result<Option<CommerceGrant>, AuthError> {
    let (client_id, redirect_uri, scope, merchant_pubkey) = match (
        req.client_id.as_deref(),
        req.redirect_uri.as_deref(),
        req.scope.as_deref(),
        req.merchant_pubkey.as_deref(),
    ) {
        (None, None, None, None) => return Ok(None),
        (Some(client_id), Some(redirect_uri), Some(scope), Some(merchant_pubkey)) => {
            (client_id, redirect_uri, scope, merchant_pubkey)
        }
        _ => {
            return Err(AuthError::BadRequest(
                "client_id, redirect_uri, scope and merchant_pubkey must be sent together"
                    .to_string(),
            ))
        }
    };

    if client_id.trim().is_empty() {
        return Err(AuthError::BadRequest("Invalid client_id".to_string()));
    }
    if scope != COMMERCE_SCOPE {
        return Err(AuthError::BadRequest("Invalid scope".to_string()));
    }
    let merchant_pubkey = PublicKey::from_hex(merchant_pubkey)
        .map_err(|_| AuthError::BadRequest("Invalid merchant_pubkey".to_string()))?;

    Ok(Some(CommerceGrant {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        merchant_pubkey,
    }))
}

fn same_origin(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// The customer's pubkey, creating the account and its key on the first click.
///
/// `local_key` becomes the key of a new account. It is ignored when the account exists:
/// an existing key is never replaced.
async fn find_or_create_customer(
    auth_state: &AuthState,
    tenant_id: i64,
    email: &str,
    local_key: Option<Keys>,
) -> Result<String, AuthError> {
    let user_repo = UserRepository::new(auth_state.state.db.clone());

    if let Some(pubkey) = user_repo.find_pubkey_by_email(email, tenant_id).await? {
        return Ok(pubkey);
    }

    let keys = local_key.unwrap_or_else(Keys::generate);
    let encrypted_secret = auth_state
        .state
        .key_manager
        .encrypt(&keys.secret_key().to_secret_bytes())
        .await
        .map_err(|e| AuthError::Internal(format!("Failed to encrypt key: {}", e)))?;

    user_repo
        .find_or_create_passwordless(
            &keys.public_key().to_hex(),
            tenant_id,
            email,
            &encrypted_secret,
        )
        .await
        .map_err(|e| match e {
            // The browser's key already belongs to another account
            RepositoryError::Duplicate => AuthError::BadRequest("Invalid local_key".to_string()),
            other => other.into(),
        })
}

/// POST /api/auth/magic-link/verify - sign in with the token from a link.
///
/// POST only, because email scanners open links with GET. The session goes in the response:
/// the orders app is a different site from this hostname, so a cookie would not reach us, and
/// the app sends it as a Bearer token. Nothing in the response identifies the customer's key.
pub async fn verify_magic_link(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    Json(req): Json<VerifyMagicLinkRequest>,
) -> Result<Response, AuthError> {
    if !tenant.0.is_customer_tenant() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let tenant_id = tenant.0.id;

    // Everything that can be checked first is, so a bad request does not use up the link
    let local_key = req
        .local_key
        .as_deref()
        .map(|key| {
            SecretKey::from_hex(key)
                .map(Keys::new)
                .map_err(|_| AuthError::BadRequest("Invalid local_key".to_string()))
        })
        .transpose()?;
    let grant = parse_commerce_grant(&req)?;

    let link = MagicLinkTokenRepository::new(auth_state.state.db.clone())
        .consume(&req.token, tenant_id)
        .await?
        .filter(|link| link.purpose == PURPOSE_SIGN_IN)
        .ok_or_else(|| AuthError::BadRequest(INVALID_LINK.to_string()))?;

    if let Some(grant) = &grant {
        if !same_origin(&grant.redirect_uri, &link.app_origin) {
            return Err(AuthError::BadRequest(
                "redirect_uri does not match the link".to_string(),
            ));
        }
    }

    let pubkey_hex =
        find_or_create_customer(&auth_state, tenant_id, &link.email, local_key).await?;

    let (session_token, authorization) = match grant {
        Some(grant) => {
            let policy_id = PolicyRepository::new(auth_state.state.db.clone())
                .find_or_create_commerce_envelope(&grant.merchant_pubkey.to_hex())
                .await?;
            let created = create_oauth_authorization(
                CreateAuthorizationParams {
                    tenant_id,
                    user_pubkey: &pubkey_hex,
                    email: &link.email,
                    client_id: &grant.client_id,
                    scope: COMMERCE_SCOPE,
                    redirect_uri: &grant.redirect_uri,
                    nsec_from_verifier: None,
                    previous_auth_id: None,
                    is_headless: false,
                    policy_id: Some(policy_id),
                },
                auth_state.clone(),
            )
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to authorize app: {:?}", e)))?;

            // This token names the new authorization, so it works on /api/nostr
            let session_token = created
                .access_token
                .ok_or_else(|| AuthError::Internal("Missing access token".to_string()))?;
            let authorization = VerifiedAuthorization {
                bunker_url: created.bunker_url,
            };
            (session_token, Some(authorization))
        }
        None => {
            let pubkey = PublicKey::from_hex(&pubkey_hex)
                .map_err(|e| AuthError::Internal(format!("Invalid pubkey: {}", e)))?;
            let session_token = generate_server_signed_ucan(
                &pubkey,
                tenant_id,
                &link.email,
                &link.app_origin,
                None,
                &auth_state.state.server_keys,
                false,
                None,
            )
            .await?;
            (session_token, None)
        }
    };

    Ok(Json(VerifyMagicLinkResponse {
        success: true,
        session_token,
        expires_in: token_expiry_seconds(),
        authorization,
    })
    .into_response())
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
