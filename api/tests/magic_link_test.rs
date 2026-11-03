#![cfg(feature = "integration-tests")]

// ABOUTME: Tests for requesting an email sign-in link
// ABOUTME: Covers token storage, throttling, the uniform answer and which tenants may use it

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::magic_link::{parse_app_url, send_sign_in_link};
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::email_service::{DevEmailSender, EmailSender};
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::redis::PrefixedRedis;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::{
    hash_magic_link_token, MagicLinkTokenRepository, PURPOSE_SIGN_IN,
};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{Keys, Url};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const TENANT_ID: i64 = 1;
const APP_URL: &str = "https://orders.example.com/signin";
const CUSTOMER_HOST: &str = "customers.magic-link.example.com";
const OWNER_HOST: &str = "owners.magic-link.example.com";

fn app_url() -> Url {
    Url::parse(APP_URL).unwrap()
}

fn unique_email() -> String {
    format!("customer-{}@example.com", Uuid::new_v4())
}

async fn test_redis() -> PrefixedRedis {
    let url =
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".to_string());
    let conn = redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .expect("Redis must be running for these tests");
    PrefixedRedis::new(conn, Some(format!("test-{}", Uuid::new_v4())))
}

fn token_from_link(link: &str) -> String {
    Url::parse(link)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
        .expect("The link should carry a token")
}

async fn row_count(pool: &PgPool, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM magic_link_tokens WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_stores_only_the_hash_and_creates_no_account() {
    let pool = common::setup_test_db().await;
    let sender = DevEmailSender::new();
    let email = unique_email();

    let sent = send_sign_in_link(
        &pool,
        None,
        &sender,
        TENANT_ID,
        &email,
        &app_url(),
        Some("203.0.113.7".parse().unwrap()),
    )
    .await;
    assert!(sent);

    let captured = sender.get_captured_emails();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].to, email);
    assert_eq!(captured[0].subject, "Sign in to example.com");
    let link = captured[0].verification_url.clone().unwrap();
    assert!(link.starts_with("https://orders.example.com/signin?token="));
    let token = token_from_link(&link);

    let (token_hash, purpose, app_origin, ip, minutes): (String, String, String, String, f64) =
        sqlx::query_as(
            "SELECT token_hash, purpose, app_origin, host(request_ip),
                    (EXTRACT(EPOCH FROM (expires_at - created_at)) / 60)::float8
             FROM magic_link_tokens WHERE email = $1",
        )
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(token_hash, hash_magic_link_token(&token));
    assert_ne!(token_hash, token);
    assert_eq!(purpose, PURPOSE_SIGN_IN);
    assert_eq!(app_origin, APP_URL);
    assert_eq!(ip, "203.0.113.7");
    assert!((minutes - 15.0).abs() < 0.1, "Expires in 15 minutes");

    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 0, "The account is created on the click, not here");
}

#[tokio::test]
async fn test_one_link_per_email_per_minute() {
    let pool = common::setup_test_db().await;
    let redis = test_redis().await;
    let sender = DevEmailSender::new();
    let email = unique_email();

    for expected in [true, false] {
        assert_eq!(
            send_sign_in_link(
                &pool,
                Some(&redis),
                &sender,
                TENANT_ID,
                &email,
                &app_url(),
                None
            )
            .await,
            expected
        );
    }

    assert_eq!(sender.get_captured_emails().len(), 1);
    assert_eq!(row_count(&pool, &email).await, 1);
}

#[tokio::test]
async fn test_five_links_per_email_per_hour() {
    let pool = common::setup_test_db().await;
    let sender = DevEmailSender::new();
    let email = unique_email();

    // No Redis here, so only the hourly count can stop it
    for _ in 0..5 {
        assert!(send_sign_in_link(&pool, None, &sender, TENANT_ID, &email, &app_url(), None).await);
    }
    assert!(!send_sign_in_link(&pool, None, &sender, TENANT_ID, &email, &app_url(), None).await);

    assert_eq!(sender.get_captured_emails().len(), 5);
    assert_eq!(row_count(&pool, &email).await, 5);
}

#[tokio::test]
async fn test_twenty_requests_per_ip_per_hour() {
    let pool = common::setup_test_db().await;
    let redis = test_redis().await;
    let sender = DevEmailSender::new();
    let ip = Some("203.0.113.8".parse().unwrap());

    for _ in 0..20 {
        assert!(
            send_sign_in_link(
                &pool,
                Some(&redis),
                &sender,
                TENANT_ID,
                &unique_email(),
                &app_url(),
                ip
            )
            .await
        );
    }
    assert!(
        !send_sign_in_link(
            &pool,
            Some(&redis),
            &sender,
            TENANT_ID,
            &unique_email(),
            &app_url(),
            ip
        )
        .await
    );
    assert_eq!(sender.get_captured_emails().len(), 20);
}

#[tokio::test]
async fn test_token_is_consumed_once_under_concurrent_clicks() {
    let pool = common::setup_test_db().await;
    let repo = MagicLinkTokenRepository::new(pool.clone());
    let email = unique_email();
    let token = Uuid::new_v4().to_string();

    repo.create(
        TENANT_ID,
        &email,
        &token,
        PURPOSE_SIGN_IN,
        APP_URL,
        Utc::now() + Duration::minutes(15),
        None,
    )
    .await
    .unwrap();

    let mut clicks = Vec::new();
    for _ in 0..10 {
        let repo = repo.clone();
        let token = token.clone();
        clicks.push(tokio::spawn(async move {
            repo.consume(&token, TENANT_ID).await.unwrap()
        }));
    }

    let mut consumed = Vec::new();
    for click in clicks {
        if let Some(link) = click.await.unwrap() {
            consumed.push(link);
        }
    }
    assert_eq!(consumed.len(), 1, "Exactly one click should succeed");
    assert_eq!(consumed[0].email, email);
    assert_eq!(consumed[0].purpose, PURPOSE_SIGN_IN);
    assert_eq!(consumed[0].app_origin, APP_URL);
}

#[tokio::test]
async fn test_expired_unknown_and_other_tenant_tokens_are_not_consumed() {
    let pool = common::setup_test_db().await;
    let repo = MagicLinkTokenRepository::new(pool.clone());
    let email = unique_email();

    let expired = Uuid::new_v4().to_string();
    repo.create(
        TENANT_ID,
        &email,
        &expired,
        PURPOSE_SIGN_IN,
        APP_URL,
        Utc::now() - Duration::minutes(1),
        None,
    )
    .await
    .unwrap();
    assert!(repo.consume(&expired, TENANT_ID).await.unwrap().is_none());

    assert!(repo
        .consume(&Uuid::new_v4().to_string(), TENANT_ID)
        .await
        .unwrap()
        .is_none());

    let other_tenant = Uuid::new_v4().to_string();
    repo.create(
        TENANT_ID,
        &email,
        &other_tenant,
        PURPOSE_SIGN_IN,
        APP_URL,
        Utc::now() + Duration::minutes(15),
        None,
    )
    .await
    .unwrap();
    assert!(repo
        .consume(&other_tenant, TENANT_ID + 1)
        .await
        .unwrap()
        .is_none());
    assert!(
        repo.consume(&other_tenant, TENANT_ID)
            .await
            .unwrap()
            .is_some(),
        "A refused attempt from another tenant must not use the token up"
    );
}

#[tokio::test]
async fn test_purge_removes_tokens_older_than_a_day() {
    let pool = common::setup_test_db().await;
    let repo = MagicLinkTokenRepository::new(pool.clone());
    let old_email = unique_email();
    let new_email = unique_email();

    for email in [&old_email, &new_email] {
        repo.create(
            TENANT_ID,
            email,
            &Uuid::new_v4().to_string(),
            PURPOSE_SIGN_IN,
            APP_URL,
            Utc::now() + Duration::minutes(15),
            None,
        )
        .await
        .unwrap();
    }
    sqlx::query(
        "UPDATE magic_link_tokens SET created_at = NOW() - INTERVAL '25 hours' WHERE email = $1",
    )
    .bind(&old_email)
    .execute(&pool)
    .await
    .unwrap();

    repo.purge_expired().await.unwrap();

    assert_eq!(row_count(&pool, &old_email).await, 0);
    assert_eq!(row_count(&pool, &new_email).await, 1);
}

// ----------------------------------------------------------------------------
// The HTTP endpoint
// ----------------------------------------------------------------------------

struct TestKeyManager;

#[async_trait::async_trait]
impl KeyManager for TestKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        Ok(plaintext_bytes.to_vec())
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

async fn upsert_tenant(pool: &PgPool, domain: &str) -> Tenant {
    sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $1, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(domain)
    .fetch_one(pool)
    .await
    .expect("Failed to create tenant")
}

async fn test_router(pool: PgPool) -> Router {
    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(1);
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager: Arc::new(Box::new(TestKeyManager)),
        signer_handlers: None,
        http_handler_cache: new_http_handler_cache(),
        server_keys: Keys::generate(),
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt_sender: bcrypt_queue.sender(),
        redis: None,
        secret_pool: secret_pool.receiver(),
        secure_cookies: false,
    });
    let _ = KEYCAST_STATE.set(state.clone());

    let tenant_cache = get_tenant_cache().unwrap();
    for domain in [CUSTOMER_HOST, OWNER_HOST] {
        let tenant = upsert_tenant(&pool, domain).await;
        tenant_cache
            .insert(domain.to_string(), Arc::new(tenant))
            .await;
    }

    Router::new().nest(
        "/api",
        api_routes(pool, state, CorsLayer::new(), CorsLayer::new(), None),
    )
}

async fn post_magic_link(
    router: &Router,
    host: &str,
    email: &str,
    app_url: &str,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/auth/magic-link")
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "email": email, "app_url": app_url }).to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

fn set_customer_env() {
    std::env::set_var("CUSTOMER_TENANT_DOMAIN", CUSTOMER_HOST);
    std::env::set_var("ALLOWED_ORIGINS", "https://orders.example.com");
}

fn clear_customer_env() {
    std::env::remove_var("CUSTOMER_TENANT_DOMAIN");
    std::env::remove_var("ALLOWED_ORIGINS");
}

#[tokio::test]
#[serial]
async fn test_answer_is_the_same_for_known_and_unknown_emails() {
    let pool = common::setup_test_db().await;
    let router = test_router(pool.clone()).await;
    set_customer_env();

    let known = unique_email();
    let customer_tenant = upsert_tenant(&pool, CUSTOMER_HOST).await.id;
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(Keys::generate().public_key().to_hex())
    .bind(customer_tenant)
    .bind(&known)
    .execute(&pool)
    .await
    .unwrap();

    let known_answer = post_magic_link(&router, CUSTOMER_HOST, &known, APP_URL).await;
    let unknown_answer = post_magic_link(&router, CUSTOMER_HOST, &unique_email(), APP_URL).await;
    clear_customer_env();

    assert_eq!(known_answer.0, StatusCode::OK);
    assert_eq!(known_answer, unknown_answer);
    assert_eq!(known_answer.1, r#"{"success":true}"#);
}

#[tokio::test]
#[serial]
async fn test_malformed_email_is_refused() {
    let pool = common::setup_test_db().await;
    let router = test_router(pool).await;
    set_customer_env();

    let (status, _) = post_magic_link(&router, CUSTOMER_HOST, "not-an-email", APP_URL).await;
    clear_customer_env();

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_app_url_must_be_on_an_allowed_origin() {
    let pool = common::setup_test_db().await;
    let router = test_router(pool).await;
    set_customer_env();

    let mut refused = Vec::new();
    for app_url in [
        "https://evil.example.org/signin",
        "https://orders.example.com.evil.example.org/signin",
        "https://user:pass@orders.example.com/signin",
        "ftp://orders.example.com/signin",
        "not a url",
    ] {
        let (status, _) = post_magic_link(&router, CUSTOMER_HOST, &unique_email(), app_url).await;
        refused.push((app_url, status));
    }
    let (allowed, _) = post_magic_link(&router, CUSTOMER_HOST, &unique_email(), APP_URL).await;
    clear_customer_env();

    for (app_url, status) in refused {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{app_url}");
    }
    assert_eq!(
        allowed,
        StatusCode::OK,
        "A path on an allowed origin is fine"
    );
}

#[tokio::test]
#[serial]
async fn test_other_tenants_have_no_email_link_sign_in() {
    let pool = common::setup_test_db().await;
    let router = test_router(pool.clone()).await;
    set_customer_env();

    let email = unique_email();
    let (on_owner_host, _) = post_magic_link(&router, OWNER_HOST, &email, APP_URL).await;
    clear_customer_env();

    // With nothing configured, not even the customer hostname has it
    std::env::set_var("ALLOWED_ORIGINS", "https://orders.example.com");
    let (unconfigured, _) = post_magic_link(&router, CUSTOMER_HOST, &email, APP_URL).await;
    clear_customer_env();

    assert_eq!(on_owner_host, StatusCode::NOT_FOUND);
    assert_eq!(unconfigured, StatusCode::NOT_FOUND);
    assert_eq!(row_count(&pool, &email).await, 0);
}

#[test]
#[serial]
fn test_parse_app_url_keeps_the_page() {
    std::env::set_var("ALLOWED_ORIGINS", "https://orders.example.com");
    let url = parse_app_url("https://orders.example.com/signin?next=cart");
    std::env::remove_var("ALLOWED_ORIGINS");

    assert_eq!(
        url.map(|url| url.to_string()),
        Some("https://orders.example.com/signin?next=cart".to_string())
    );
}
