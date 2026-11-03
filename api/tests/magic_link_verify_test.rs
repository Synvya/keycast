#![cfg(feature = "integration-tests")]

// ABOUTME: Tests for signing in with an email link and what the session can then do
// ABOUTME: Drives the real routes, including /api/nostr under the commerce permission

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::{BcryptQueue, STALE_SIGNUP_CONDITION};
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::{
    MagicLinkTokenRepository, PURPOSE_DELETE_ACCOUNT, PURPOSE_SIGN_IN,
};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{EventBuilder, Keys, Kind, Tag};
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const CUSTOMER_HOST: &str = "customers.magic-link-verify.example.com";
const OWNER_HOST: &str = "owners.magic-link-verify.example.com";
const APP_URL: &str = "https://orders.example.com/signin";

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

struct TestApp {
    pool: PgPool,
    router: Router,
    customer_tenant: i64,
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

async fn setup() -> TestApp {
    let pool = common::setup_test_db().await;

    if std::env::var("SERVER_NSEC").is_err() {
        std::env::set_var("SERVER_NSEC", "0".repeat(63) + "1");
    }
    let server_keys = Keys::parse(&std::env::var("SERVER_NSEC").unwrap()).unwrap();
    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.com");
    std::env::set_var("CUSTOMER_TENANT_DOMAIN", CUSTOMER_HOST);
    std::env::set_var("ALLOWED_ORIGINS", "https://orders.example.com");

    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(4);
    secret_pool.spawn_producer();

    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager: Arc::new(Box::new(TestKeyManager)),
        signer_handlers: None,
        http_handler_cache: new_http_handler_cache(),
        server_keys,
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt_sender: bcrypt_queue.sender(),
        redis: None,
        secret_pool: secret_pool.receiver(),
        secure_cookies: false,
    });
    let _ = KEYCAST_STATE.set(state.clone());

    let customer = upsert_tenant(&pool, CUSTOMER_HOST).await;
    let owner = upsert_tenant(&pool, OWNER_HOST).await;
    let customer_tenant = customer.id;
    let tenant_cache = get_tenant_cache().unwrap();
    tenant_cache
        .insert(CUSTOMER_HOST.to_string(), Arc::new(customer))
        .await;
    tenant_cache
        .insert(OWNER_HOST.to_string(), Arc::new(owner))
        .await;

    let router = Router::new().nest(
        "/api",
        api_routes(
            pool.clone(),
            state,
            CorsLayer::new(),
            CorsLayer::new(),
            None,
        ),
    );

    TestApp {
        pool,
        router,
        customer_tenant,
    }
}

fn unique_email() -> String {
    format!("customer-{}@example.com", Uuid::new_v4())
}

async fn new_link_for(
    app: &TestApp,
    email: &str,
    purpose: &str,
    expires_in_minutes: i64,
) -> String {
    let token = Uuid::new_v4().to_string();
    MagicLinkTokenRepository::new(app.pool.clone())
        .create(
            app.customer_tenant,
            email,
            &token,
            purpose,
            APP_URL,
            Utc::now() + Duration::minutes(expires_in_minutes),
            None,
        )
        .await
        .unwrap();
    token
}

struct Answer {
    status: StatusCode,
    body: Value,
    raw: String,
    set_cookie: bool,
}

async fn request(
    app: &TestApp,
    method: Method,
    host: &str,
    path: &str,
    bearer: Option<&str>,
    body: Value,
) -> Answer {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let set_cookie = response.headers().contains_key(header::SET_COOKIE);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw = String::from_utf8_lossy(&bytes).to_string();
    Answer {
        status,
        body: serde_json::from_str(&raw).unwrap_or(Value::Null),
        raw,
        set_cookie,
    }
}

async fn verify(app: &TestApp, body: Value) -> Answer {
    request(
        app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        body,
    )
    .await
}

fn commerce_grant(token: &str, merchant: &str) -> Value {
    json!({
        "token": token,
        "client_id": "orders.example.com",
        "redirect_uri": APP_URL,
        "scope": "policy:commerce_envelope",
        "merchant_pubkey": merchant,
    })
}

async fn account_pubkey(app: &TestApp, email: &str) -> Option<String> {
    sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = $2")
        .bind(email)
        .bind(app.customer_tenant)
        .fetch_optional(&app.pool)
        .await
        .unwrap()
}

async fn rpc(app: &TestApp, session: &str, method: &str, params: Value) -> Answer {
    request(
        app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/nostr",
        Some(session),
        json!({ "method": method, "params": params }),
    )
    .await
}

#[tokio::test]
#[serial]
async fn test_first_click_creates_the_account_and_a_key() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;

    let answer = verify(&app, json!({ "token": token })).await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert_eq!(answer.body["success"], true);
    assert!(answer.body["session_token"].is_string());
    assert!(answer.body["expires_in"].as_i64().unwrap() > 0);
    assert!(answer.body.get("authorization").is_none());
    assert!(!answer.set_cookie, "Customers get no cookie");

    let pubkey = account_pubkey(&app, &email).await.expect("Account created");
    assert!(!answer.raw.contains(&pubkey), "Never returns the pubkey");
    assert!(!answer.raw.contains("npub"), "Never returns an npub");

    let (verified, password, verification_token): (bool, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT email_verified, password_hash, email_verification_token
             FROM users WHERE pubkey = $1",
        )
        .bind(&pubkey)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(verified);
    assert_eq!(password, None);
    assert_eq!(verification_token, None);

    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(keys, 1);
}

#[tokio::test]
#[serial]
async fn test_account_survives_the_signup_cleanup() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    assert_eq!(
        verify(&app, json!({ "token": token })).await.status,
        StatusCode::OK
    );
    let pubkey = account_pubkey(&app, &email).await.unwrap();

    sqlx::query("UPDATE users SET created_at = NOW() - INTERVAL '15 minutes' WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&app.pool)
        .await
        .unwrap();
    let deleted = sqlx::query(&format!(
        "DELETE FROM users WHERE {STALE_SIGNUP_CONDITION} AND pubkey = $1"
    ))
    .bind(&pubkey)
    .execute(&app.pool)
    .await
    .unwrap();

    assert_eq!(deleted.rows_affected(), 0);
}

#[tokio::test]
#[serial]
async fn test_a_link_works_once() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;

    assert_eq!(
        verify(&app, json!({ "token": token })).await.status,
        StatusCode::OK
    );

    let second = verify(&app, json!({ "token": token })).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert!(
        second.raw.contains("invalid_or_expired_link"),
        "{}",
        second.raw
    );
}

#[tokio::test]
#[serial]
async fn test_bad_links_all_fail_the_same_way() {
    let app = setup().await;

    let expired = new_link_for(&app, &unique_email(), PURPOSE_SIGN_IN, -1).await;
    // For an email with no account, a deletion link is as good as unknown
    let wrong_purpose = new_link_for(&app, &unique_email(), PURPOSE_DELETE_ACCOUNT, 15).await;
    let other_tenant = Uuid::new_v4().to_string();
    MagicLinkTokenRepository::new(app.pool.clone())
        .create(
            app.customer_tenant + 1_000_000,
            &unique_email(),
            &other_tenant,
            PURPOSE_SIGN_IN,
            APP_URL,
            Utc::now() + Duration::minutes(15),
            None,
        )
        .await
        .unwrap();

    let mut answers = Vec::new();
    for token in [
        expired,
        wrong_purpose,
        other_tenant,
        Uuid::new_v4().to_string(),
    ] {
        answers.push(verify(&app, json!({ "token": token })).await);
    }

    for answer in &answers {
        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        assert_eq!(answer.raw, answers[0].raw, "All the same answer");
        assert!(answer.raw.contains("invalid_or_expired_link"));
    }
}

#[tokio::test]
#[serial]
async fn test_get_does_not_consume_a_token() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;

    let scanner = request(
        &app,
        Method::GET,
        CUSTOMER_HOST,
        &format!("/api/auth/magic-link/verify?token={token}"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(scanner.status, StatusCode::METHOD_NOT_ALLOWED);

    assert_eq!(
        verify(&app, json!({ "token": token })).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
#[serial]
async fn test_existing_account_keeps_its_key_and_local_key_is_ignored() {
    let app = setup().await;
    let email = unique_email();
    let first = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    assert_eq!(
        verify(&app, json!({ "token": first })).await.status,
        StatusCode::OK
    );
    let pubkey = account_pubkey(&app, &email).await.unwrap();

    let second = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let browser_key = Keys::generate();
    let answer = verify(
        &app,
        json!({ "token": second, "local_key": browser_key.secret_key().to_secret_hex() }),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert_eq!(account_pubkey(&app, &email).await.unwrap(), pubkey);
    let browser_user: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(browser_key.public_key().to_hex())
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(browser_user, 0);
}

#[tokio::test]
#[serial]
async fn test_local_key_becomes_the_key_of_a_new_account() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let browser_key = Keys::generate();

    let answer = verify(
        &app,
        json!({ "token": token, "local_key": browser_key.secret_key().to_secret_hex() }),
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert_eq!(
        account_pubkey(&app, &email).await.unwrap(),
        browser_key.public_key().to_hex()
    );
}

#[tokio::test]
#[serial]
async fn test_invalid_local_key_creates_nothing_and_keeps_the_link() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;

    let answer = verify(&app, json!({ "token": token, "local_key": "not-a-key" })).await;

    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(account_pubkey(&app, &email).await, None);
    assert_eq!(
        verify(&app, json!({ "token": token })).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
#[serial]
async fn test_local_key_of_another_account_is_refused() {
    let app = setup().await;
    let taken = Keys::generate();
    let first_email = unique_email();
    let first = new_link_for(&app, &first_email, PURPOSE_SIGN_IN, 15).await;
    let local_key = taken.secret_key().to_secret_hex();
    assert_eq!(
        verify(&app, json!({ "token": first, "local_key": local_key }))
            .await
            .status,
        StatusCode::OK
    );

    let second_email = unique_email();
    let second = new_link_for(&app, &second_email, PURPOSE_SIGN_IN, 15).await;
    let answer = verify(&app, json!({ "token": second, "local_key": local_key })).await;

    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(account_pubkey(&app, &second_email).await, None);
}

#[tokio::test]
#[serial]
async fn test_grant_fields_come_together_and_are_checked() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let merchant = Keys::generate().public_key().to_hex();

    let mut partial = commerce_grant(&token, &merchant);
    partial.as_object_mut().unwrap().remove("merchant_pubkey");
    let mut wrong_scope = commerce_grant(&token, &merchant);
    wrong_scope["scope"] = json!("policy:full");

    for body in [partial, wrong_scope, commerce_grant(&token, "not-a-pubkey")] {
        assert_eq!(verify(&app, body).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(account_pubkey(&app, &email).await, None);

    // None of those used up the link
    assert_eq!(
        verify(&app, commerce_grant(&token, &merchant)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
#[serial]
async fn test_redirect_uri_must_match_the_links_origin() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let merchant = Keys::generate().public_key().to_hex();

    let mut body = commerce_grant(&token, &merchant);
    body["redirect_uri"] = json!("https://evil.example.org/signin");

    assert_eq!(verify(&app, body).await.status, StatusCode::BAD_REQUEST);
    let authorizations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations WHERE redirect_origin = 'https://evil.example.org'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(authorizations, 0);
}

/// A sign-in that grants the permission: the session can place an order, and nothing else.
#[tokio::test]
#[serial]
async fn test_session_places_orders_with_one_merchant_and_nothing_else() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let merchant = Keys::generate().public_key();
    let other_merchant = Keys::generate().public_key();

    let answer = verify(&app, commerce_grant(&token, &merchant.to_hex())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert!(answer.body["authorization"]["bunker_url"]
        .as_str()
        .unwrap()
        .starts_with("bunker://"));
    assert!(!answer.set_cookie);

    let pubkey_hex = account_pubkey(&app, &email).await.unwrap();
    let pubkey = nostr_sdk::PublicKey::from_hex(&pubkey_hex).unwrap();
    assert!(
        !answer.raw.contains(&pubkey_hex),
        "Never returns the pubkey"
    );
    let session = answer.body["session_token"].as_str().unwrap();

    let order = serde_json::to_string(
        &EventBuilder::new(Kind::from(1327), "order")
            .tag(Tag::public_key(merchant))
            .build(pubkey),
    )
    .unwrap();
    let order_for_other = serde_json::to_string(
        &EventBuilder::new(Kind::from(1327), "order")
            .tag(Tag::public_key(other_merchant))
            .build(pubkey),
    )
    .unwrap();
    let event_json = |kind: u16| {
        serde_json::to_value(EventBuilder::new(Kind::from(kind), "x").build(pubkey)).unwrap()
    };

    // Allowed: encrypt the order to the merchant and to the customer's own key, sign the seal
    assert_eq!(
        rpc(
            &app,
            session,
            "nip44_encrypt",
            json!([merchant.to_hex(), order])
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(
        rpc(&app, session, "nip44_encrypt", json!([pubkey_hex, order]))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        rpc(&app, session, "sign_event", json!([event_json(13)]))
            .await
            .status,
        StatusCode::OK
    );

    // Refused: another recipient, another merchant's order, a plain message, signing anything else
    for (recipient, plaintext) in [
        (other_merchant.to_hex(), order.clone()),
        (merchant.to_hex(), order_for_other),
        (merchant.to_hex(), "hello".to_string()),
    ] {
        let refused = rpc(
            &app,
            session,
            "nip44_encrypt",
            json!([recipient, plaintext]),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.raw);
    }
    for kind in [0, 1, 1327, 1059] {
        let refused = rpc(&app, session, "sign_event", json!([event_json(kind)])).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "kind {kind}: {}",
            refused.raw
        );
    }
}

#[tokio::test]
#[serial]
async fn test_session_without_a_grant_cannot_sign() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let answer = verify(&app, json!({ "token": token })).await;
    let session = answer.body["session_token"].as_str().unwrap();

    let refused = rpc(&app, session, "get_public_key", json!([])).await;

    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.raw);
}

/// The rest of the API does not exist on the customer hostname, even with a valid session.
#[tokio::test]
#[serial]
async fn test_customer_hostname_has_only_customer_routes() {
    let app = setup().await;
    let email = unique_email();
    let token = new_link_for(&app, &email, PURPOSE_SIGN_IN, 15).await;
    let answer = verify(
        &app,
        commerce_grant(&token, &Keys::generate().public_key().to_hex()),
    )
    .await;
    let session = answer.body["session_token"].as_str().unwrap();

    for (method, path) in [
        (Method::POST, "/api/user/bunker/create"),
        (Method::POST, "/api/user/sign"),
        (Method::POST, "/api/user/export-key"),
        (Method::POST, "/api/user/change-key"),
        (Method::POST, "/api/user/change-password"),
        (Method::GET, "/api/user/bunker"),
        (Method::POST, "/api/auth/login"),
        (Method::POST, "/api/auth/register"),
        (Method::POST, "/api/auth/forgot-password"),
        (Method::POST, "/api/auth/resend-verification"),
        (Method::GET, "/api/oauth/authorize"),
        (Method::POST, "/api/oauth/token"),
        (Method::POST, "/api/headless/register"),
        (Method::GET, "/api/teams"),
        (Method::GET, "/api/admin/status"),
    ] {
        let refused = request(
            &app,
            method.clone(),
            CUSTOMER_HOST,
            path,
            Some(session),
            json!({}),
        )
        .await;
        assert_eq!(refused.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[tokio::test]
#[serial]
async fn test_guard_leaves_other_hostnames_alone() {
    let app = setup().await;

    for (method, path) in [
        (Method::POST, "/api/auth/login"),
        (Method::POST, "/api/auth/forgot-password"),
        (Method::GET, "/api/teams"),
    ] {
        let answer = request(&app, method.clone(), OWNER_HOST, path, None, json!({})).await;
        assert_ne!(answer.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[tokio::test]
#[serial]
async fn test_verify_does_not_exist_on_other_hostnames() {
    let app = setup().await;
    let token = new_link_for(&app, &unique_email(), PURPOSE_SIGN_IN, 15).await;

    let answer = request(
        &app,
        Method::POST,
        OWNER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({ "token": token }),
    )
    .await;

    assert_eq!(answer.status, StatusCode::NOT_FOUND);
}
