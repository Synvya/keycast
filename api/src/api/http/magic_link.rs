// ABOUTME: Email-link sign-in for customer accounts, which have no password
// ABOUTME: Requesting a link never creates an account and answers the same for any email

use super::auth::{
    delete_account, generate_secure_token, generate_server_signed_ucan,
    generate_server_signed_ucan_with_lifetime, token_expiry_seconds, AuthError,
    DeleteAccountResponse,
};
use super::oauth::{create_oauth_authorization, CreateAuthorizationParams};
use super::routes::AuthState;
use crate::api::tenant::TenantExtractor;
use crate::email_service::{EmailSender, EmailService};
use crate::handlers::http_rpc_handler::invalidate_handlers_for_bunker;
use crate::rate_limit;
use crate::redis::PrefixedRedis;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use keycast_core::authorization_channel::AuthorizationCommand;
use keycast_core::repositories::{
    CustomerAppOriginRepository, MagicLinkTokenRepository, OAuthAuthorizationRepository,
    PolicyRepository, RefreshTokenRepository, RepositoryError, UserRepository,
    PURPOSE_DELETE_ACCOUNT, PURPOSE_SIGN_IN,
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
/// How long the session from a deletion link lasts.
const DELETE_SESSION_SECONDS: i64 = 600;
/// One answer for an unknown, used, expired or other-tenant token.
const INVALID_LINK: &str = "invalid_or_expired_link";

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    /// Who to send a sign-in link to. A deletion link goes to the signed-in customer instead.
    pub email: Option<String>,
    pub app_url: String,
    /// "sign_in" (the default) or "delete_account"
    pub purpose: Option<String>,
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

/// Parse the page a link should land on, if it is on a merchant's allowed origin. Returns the
/// page and the merchant's name, which comes from our table rather than the request, so a
/// caller cannot put arbitrary text in the email.
pub async fn allowed_app_url(
    pool: &PgPool,
    tenant_id: i64,
    app_url: &str,
) -> Result<Option<(Url, String)>, RepositoryError> {
    let Ok(url) = Url::parse(app_url.trim()) else {
        return Ok(None);
    };
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Ok(None);
    }

    let merchant_name = CustomerAppOriginRepository::new(pool.clone())
        .find_merchant_name(tenant_id, &url.origin().ascii_serialization())
        .await?;
    Ok(merchant_name.map(|merchant_name| (url, merchant_name)))
}

/// The link to send: the app's page with the token added to its query string.
pub fn magic_link(app_url: &Url, token: &str) -> String {
    let mut link = app_url.clone();
    link.set_fragment(None);
    link.query_pairs_mut().append_pair("token", token);
    link.to_string()
}

/// A link to send.
pub struct LinkRequest<'a> {
    pub tenant_id: i64,
    pub email: &'a str,
    pub app_url: &'a Url,
    pub merchant_name: &'a str,
    pub purpose: &'a str,
    pub request_ip: Option<IpAddr>,
}

/// Apply the limits, store the token and send the email. Returns whether a link was sent.
///
/// Throttled requests send nothing and are only logged: the caller's answer never changes.
pub async fn send_link(
    pool: &PgPool,
    redis: Option<&PrefixedRedis>,
    email_sender: &dyn EmailSender,
    request: LinkRequest<'_>,
) -> bool {
    let LinkRequest {
        tenant_id,
        email,
        app_url,
        merchant_name,
        purpose,
        request_ip,
    } = request;

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
            purpose,
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
    let sent = if purpose == PURPOSE_DELETE_ACCOUNT {
        email_sender
            .send_delete_account_email(email, &link, merchant_name)
            .await
    } else {
        email_sender
            .send_magic_link_email(email, &link, merchant_name)
            .await
    };
    if let Err(e) = sent {
        tracing::error!("Failed to send sign-in link: {}", e);
        return false;
    }

    true
}

/// The pubkey of the customer signed in with this request's Bearer session.
async fn signed_in_customer(headers: &HeaderMap, tenant_id: i64) -> Result<String, AuthError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::MissingToken)?;
    let (pubkey, _, _, _) = crate::ucan_auth::validate_ucan_token(auth_header, tenant_id)
        .await
        .map_err(|_| AuthError::InvalidToken)?;
    Ok(pubkey)
}

/// The email of the customer signed in with this request's Bearer session.
async fn signed_in_customer_email(
    pool: &PgPool,
    headers: &HeaderMap,
    tenant_id: i64,
) -> Result<String, AuthError> {
    let pubkey = signed_in_customer(headers, tenant_id).await?;
    UserRepository::new(pool.clone())
        .get_email(&pubkey, tenant_id)
        .await
        .map_err(|_| AuthError::InvalidToken)
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

    let tenant_id = tenant.0.id;
    let purpose = req.purpose.as_deref().unwrap_or(PURPOSE_SIGN_IN);
    let email = match purpose {
        PURPOSE_SIGN_IN => req.email.as_deref().and_then(normalize_email),
        // Only for the signed-in customer, and only ever to their own address
        PURPOSE_DELETE_ACCOUNT => {
            Some(signed_in_customer_email(&auth_state.state.db, &headers, tenant_id).await?)
        }
        _ => return Err(AuthError::BadRequest("Invalid purpose".to_string())),
    }
    .ok_or_else(|| AuthError::BadRequest("Invalid email address".to_string()))?;
    let purpose = purpose.to_string();
    let (app_url, merchant_name) = allowed_app_url(&auth_state.state.db, tenant_id, &req.app_url)
        .await?
        .ok_or_else(|| AuthError::BadRequest("app_url is not allowed".to_string()))?;

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
        send_link(
            &state.db,
            state.redis.as_ref(),
            email_service.sender(),
            LinkRequest {
                tenant_id,
                email: &email,
                app_url: &app_url,
                merchant_name: &merchant_name,
                purpose: &purpose,
                request_ip,
            },
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

/// The answer to a deletion link: a short session, and the only kind allowed to delete an
/// account. An ordinary session, even a stolen one, cannot delete.
async fn delete_session(
    auth_state: &AuthState,
    tenant_id: i64,
    email: &str,
    app_url: &str,
) -> Result<Response, AuthError> {
    let pubkey_hex = UserRepository::new(auth_state.state.db.clone())
        .find_pubkey_by_email(email, tenant_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(INVALID_LINK.to_string()))?;
    let pubkey = PublicKey::from_hex(&pubkey_hex)
        .map_err(|e| AuthError::Internal(format!("Invalid pubkey: {}", e)))?;

    let session_token = generate_server_signed_ucan_with_lifetime(
        &pubkey,
        tenant_id,
        email,
        app_url,
        None,
        &auth_state.state.server_keys,
        true,
        None,
        DELETE_SESSION_SECONDS as u64,
    )
    .await?;

    Ok(Json(VerifyMagicLinkResponse {
        success: true,
        session_token,
        expires_in: DELETE_SESSION_SECONDS,
        authorization: None,
    })
    .into_response())
}

/// DELETE /api/customer/account - delete the signed-in customer's account.
///
/// Public CORS, unlike /user/account, because each merchant's orders app is its own origin and
/// sends a Bearer token. Only the session from a deletion link passes the check inside.
pub async fn delete_customer_account(
    tenant: TenantExtractor,
    state: State<AuthState>,
    headers: HeaderMap,
) -> Result<Json<DeleteAccountResponse>, Response> {
    if !tenant.0.is_customer_tenant() {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    delete_account(tenant, state, headers)
        .await
        .map_err(IntoResponse::into_response)
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
        .ok_or_else(|| AuthError::BadRequest(INVALID_LINK.to_string()))?;

    if link.purpose == PURPOSE_DELETE_ACCOUNT {
        return delete_session(&auth_state, tenant_id, &link.email, &link.app_origin).await;
    }

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

#[derive(Debug, Serialize)]
pub struct CustomerApp {
    pub app_origin: String,
    pub merchant_name: Option<String>,
    pub granted_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CustomerAppsResponse {
    pub authorizations: Vec<CustomerApp>,
}

/// GET /api/customer/authorizations - the apps that can act for the signed-in customer.
pub async fn list_customer_apps(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    if !tenant.0.is_customer_tenant() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let tenant_id = tenant.0.id;
    let pubkey = signed_in_customer(&headers, tenant_id).await?;

    let authorizations = OAuthAuthorizationRepository::new(auth_state.state.db.clone())
        .list_customer_apps(&pubkey, tenant_id)
        .await?
        .into_iter()
        .map(|(app_origin, merchant_name, granted_at)| CustomerApp {
            app_origin,
            merchant_name,
            granted_at,
        })
        .collect();

    Ok(Json(CustomerAppsResponse { authorizations }).into_response())
}

#[derive(Debug, Deserialize)]
pub struct RevokeCustomerAppRequest {
    pub app_origin: String,
}

/// POST /api/customer/authorizations/revoke - stop an app acting for the signed-in customer.
/// Takes effect on the app's next call. Other apps keep working.
pub async fn revoke_customer_app(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<RevokeCustomerAppRequest>,
) -> Result<Response, AuthError> {
    if !tenant.0.is_customer_tenant() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let tenant_id = tenant.0.id;
    let pubkey = signed_in_customer(&headers, tenant_id).await?;

    let revoked = OAuthAuthorizationRepository::new(auth_state.state.db.clone())
        .revoke_by_origin(&pubkey, &req.app_origin, tenant_id)
        .await?;
    if revoked.is_empty() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let refresh_tokens = RefreshTokenRepository::new(auth_state.state.db.clone());
    for (authorization_id, bunker_pubkey) in &revoked {
        refresh_tokens
            .revoke_for_authorization(*authorization_id)
            .await?;
        invalidate_handlers_for_bunker(&auth_state.state.http_handler_cache, bunker_pubkey);

        if let Some(tx) = &auth_state.auth_tx {
            if let Err(e) = tx
                .send(AuthorizationCommand::Remove {
                    bunker_pubkey: bunker_pubkey.clone(),
                })
                .await
            {
                tracing::warn!("Failed to notify signer of revocation: {}", e);
            }
        }
    }

    Ok(Json(serde_json::json!({ "success": true })).into_response())
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
