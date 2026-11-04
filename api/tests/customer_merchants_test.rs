#![cfg(feature = "integration-tests")]

// ABOUTME: Tests that one customer account works across every merchant's orders app
// ABOUTME: Covers adding a merchant with no deploy, and listing and revoking apps

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::{MagicLinkTokenRepository, PURPOSE_SIGN_IN};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{Keys, ToBech32};
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const CUSTOMER_HOST: &str = "customers.merchants.example.com";
const OWNER_HOST: &str = "owners.merchants.example.com";

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
    server_keys: Keys,
    customer_tenant: i64,
    owner_tenant: i64,
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

    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(4);
    secret_pool.spawn_producer();
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager: Arc::new(Box::new(TestKeyManager)),
        signer_handlers: None,
        http_handler_cache: new_http_handler_cache(),
        server_keys: server_keys.clone(),
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt_sender: bcrypt_queue.sender(),
        redis: None,
        secret_pool: secret_pool.receiver(),
        secure_cookies: false,
    });
    let _ = KEYCAST_STATE.set(state.clone());

    let customer = upsert_tenant(&pool, CUSTOMER_HOST).await;
    let owner = upsert_tenant(&pool, OWNER_HOST).await;
    let (customer_tenant, owner_tenant) = (customer.id, owner.id);
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
        server_keys,
        customer_tenant,
        owner_tenant,
    }
}

struct Answer {
    status: StatusCode,
    body: Value,
    raw: String,
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw = String::from_utf8_lossy(&bytes).to_string();
    Answer {
        status,
        body: serde_json::from_str(&raw).unwrap_or(Value::Null),
        raw,
    }
}

async fn admin_session(app: &TestApp, role: Option<&str>) -> String {
    generate_server_signed_ucan(
        &Keys::generate().public_key(),
        app.owner_tenant,
        "admin@example.com",
        "https://admin.example.com",
        None,
        &app.server_keys,
        false,
        role,
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap()
}

fn unique_origin() -> String {
    format!("https://orders.merchant-{}.example.com", Uuid::new_v4())
}

/// Put an app on the approved list. Returns its merchant's key in hex.
async fn add_merchant(app: &TestApp, origin: &str, merchant_name: &str) -> String {
    let merchant = Keys::generate().public_key().to_hex();
    let admin = admin_session(app, Some("full")).await;
    let answer = request(
        app,
        Method::POST,
        OWNER_HOST,
        "/api/admin/customer-origins",
        Some(&admin),
        json!({ "origin": origin, "merchant_name": merchant_name, "merchant_pubkey": merchant }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    merchant
}

/// Sign in at a merchant's origin, granting the app the commerce permission.
async fn sign_in_at(app: &TestApp, email: &str, origin: &str, merchant: &str) -> Answer {
    let token = Uuid::new_v4().to_string();
    let page = format!("{origin}/signin");
    MagicLinkTokenRepository::new(app.pool.clone())
        .create(
            app.customer_tenant,
            email,
            &token,
            PURPOSE_SIGN_IN,
            &page,
            Utc::now() + Duration::minutes(15),
            None,
        )
        .await
        .unwrap();
    request(
        app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({
            "token": token,
            "client_id": origin,
            "redirect_uri": page,
            "scope": "policy:commerce_envelope",
            "merchant_pubkey": merchant,
        }),
    )
    .await
}

async fn rpc_status(app: &TestApp, session: &str) -> StatusCode {
    request(
        app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/nostr",
        Some(session),
        json!({ "method": "get_public_key", "params": [] }),
    )
    .await
    .status
}

fn session_of(answer: &Answer) -> String {
    answer.body["session_token"].as_str().unwrap().to_string()
}

fn unique_email() -> String {
    format!("customer-{}@example.com", Uuid::new_v4())
}

#[tokio::test]
#[serial]
async fn test_same_email_on_two_merchants_is_one_key_and_two_authorizations() {
    let app = setup().await;
    let email = unique_email();
    let first = unique_origin();
    let second = unique_origin();
    let first_merchant = add_merchant(&app, &first, "First Shop").await;
    let second_merchant = add_merchant(&app, &second, "Second Shop").await;

    let at_first = sign_in_at(&app, &email, &first, &first_merchant).await;
    let at_second = sign_in_at(&app, &email, &second, &second_merchant).await;
    assert_eq!(at_first.status, StatusCode::OK, "{}", at_first.raw);
    assert_eq!(at_second.status, StatusCode::OK, "{}", at_second.raw);

    let pubkeys: Vec<String> = sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1")
        .bind(&email)
        .fetch_all(&app.pool)
        .await
        .unwrap();
    assert_eq!(pubkeys.len(), 1, "One account");

    let origins: Vec<String> = sqlx::query_scalar(
        "SELECT redirect_origin FROM oauth_authorizations WHERE user_pubkey = $1 ORDER BY id",
    )
    .bind(&pubkeys[0])
    .fetch_all(&app.pool)
    .await
    .unwrap();
    assert_eq!(origins, vec![first, second], "Two authorizations");
}

#[tokio::test]
#[serial]
async fn test_account_page_lists_apps_and_revoking_one_leaves_the_other_working() {
    let app = setup().await;
    let email = unique_email();
    let first = unique_origin();
    let second = unique_origin();
    let first_merchant = add_merchant(&app, &first, "First Shop").await;
    let second_merchant = add_merchant(&app, &second, "Second Shop").await;

    let at_first = sign_in_at(&app, &email, &first, &first_merchant).await;
    let at_second = sign_in_at(&app, &email, &second, &second_merchant).await;
    let first_session = session_of(&at_first);
    let second_session = session_of(&at_second);
    assert_eq!(rpc_status(&app, &first_session).await, StatusCode::OK);
    assert_eq!(rpc_status(&app, &second_session).await, StatusCode::OK);

    let listed = request(
        &app,
        Method::GET,
        CUSTOMER_HOST,
        "/api/customer/authorizations",
        Some(&second_session),
        Value::Null,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.raw);
    let authorizations = listed.body["authorizations"].as_array().unwrap();
    assert_eq!(authorizations.len(), 2);
    assert_eq!(authorizations[0]["app_origin"], first.as_str());
    assert_eq!(authorizations[0]["merchant_name"], "First Shop");
    assert!(authorizations[0]["granted_at"].is_string());
    assert_eq!(authorizations[1]["app_origin"], second.as_str());

    let pubkey: String = sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(!listed.raw.contains(&pubkey), "Never returns the pubkey");
    assert!(!listed.raw.contains("bunker"), "Never returns key material");

    let revoked = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/customer/authorizations/revoke",
        Some(&second_session),
        json!({ "app_origin": first }),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.raw);

    assert_eq!(
        rpc_status(&app, &first_session).await,
        StatusCode::UNAUTHORIZED,
        "The revoked app stops on its next call"
    );
    assert_eq!(rpc_status(&app, &second_session).await, StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_signing_in_twice_at_one_merchant_lists_one_app_and_revoke_stops_both() {
    let app = setup().await;
    let email = unique_email();
    let origin = unique_origin();
    let merchant = add_merchant(&app, &origin, "Shop").await;

    let first = session_of(&sign_in_at(&app, &email, &origin, &merchant).await);
    let second = session_of(&sign_in_at(&app, &email, &origin, &merchant).await);

    let listed = request(
        &app,
        Method::GET,
        CUSTOMER_HOST,
        "/api/customer/authorizations",
        Some(&second),
        Value::Null,
    )
    .await;
    assert_eq!(listed.body["authorizations"].as_array().unwrap().len(), 1);

    let revoked = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/customer/authorizations/revoke",
        Some(&second),
        json!({ "app_origin": origin }),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.raw);

    assert_eq!(rpc_status(&app, &first).await, StatusCode::UNAUTHORIZED);
    assert_eq!(rpc_status(&app, &second).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_cannot_revoke_an_app_the_customer_has_not_granted() {
    let app = setup().await;
    let email = unique_email();
    let origin = unique_origin();
    let merchant = add_merchant(&app, &origin, "Shop").await;
    let session = session_of(&sign_in_at(&app, &email, &origin, &merchant).await);

    let other_customer_origin = unique_origin();
    let other_merchant = add_merchant(&app, &other_customer_origin, "Other Shop").await;
    let other_customer = session_of(
        &sign_in_at(
            &app,
            &unique_email(),
            &other_customer_origin,
            &other_merchant,
        )
        .await,
    );

    let revoked = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/customer/authorizations/revoke",
        Some(&session),
        json!({ "app_origin": other_customer_origin }),
    )
    .await;

    assert_eq!(revoked.status, StatusCode::NOT_FOUND);
    assert_eq!(rpc_status(&app, &other_customer).await, StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_account_page_needs_a_session() {
    let app = setup().await;

    let listed = request(
        &app,
        Method::GET,
        CUSTOMER_HOST,
        "/api/customer/authorizations",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(listed.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_new_merchant_works_at_once_and_stops_when_removed() {
    let app = setup().await;
    let origin = unique_origin();
    let email_request =
        |email: String| json!({ "email": email, "app_url": format!("{origin}/signin") });

    let before = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link",
        None,
        email_request(unique_email()),
    )
    .await;
    assert_eq!(before.status, StatusCode::BAD_REQUEST, "Not added yet");

    let merchant = add_merchant(&app, &origin, "New Shop").await;

    let added = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link",
        None,
        email_request(unique_email()),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.raw);

    let admin = admin_session(&app, Some("full")).await;
    let listed = request(
        &app,
        Method::GET,
        OWNER_HOST,
        "/api/admin/customer-origins",
        Some(&admin),
        Value::Null,
    )
    .await;
    assert!(
        listed.body.as_array().unwrap().iter().any(|row| {
            row["origin"] == origin.as_str()
                && row["merchant_name"] == "New Shop"
                && row["merchant_pubkey"] == merchant.as_str()
        }),
        "{}",
        listed.raw
    );

    let removed = request(
        &app,
        Method::DELETE,
        OWNER_HOST,
        "/api/admin/customer-origins",
        Some(&admin),
        json!({ "origin": origin }),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.raw);
    assert_eq!(removed.body["removed"], true);

    let after = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link",
        None,
        email_request(unique_email()),
    )
    .await;
    assert_eq!(after.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_only_a_full_admin_manages_merchants() {
    let app = setup().await;
    let body = json!({
        "origin": unique_origin(),
        "merchant_name": "Shop",
        "merchant_pubkey": Keys::generate().public_key().to_hex(),
    });

    for session in [
        admin_session(&app, None).await,
        admin_session(&app, Some("support")).await,
    ] {
        let refused = request(
            &app,
            Method::POST,
            OWNER_HOST,
            "/api/admin/customer-origins",
            Some(&session),
            body.clone(),
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.raw);
    }
}

#[tokio::test]
#[serial]
async fn test_merchant_origin_must_be_a_plain_web_origin() {
    let app = setup().await;
    let admin = admin_session(&app, Some("full")).await;
    let merchant = Keys::generate().public_key().to_hex();

    for origin in [
        "http://orders.example.com",
        "https://orders.example.com/signin",
        "https://user:pass@orders.example.com",
        "ftp://orders.example.com",
        "not a url",
    ] {
        let refused = request(
            &app,
            Method::POST,
            OWNER_HOST,
            "/api/admin/customer-origins",
            Some(&admin),
            json!({ "origin": origin, "merchant_name": "Shop", "merchant_pubkey": merchant }),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{origin}");
    }
}

#[tokio::test]
#[serial]
async fn test_adding_a_merchant_needs_a_valid_key() {
    let app = setup().await;
    let admin = admin_session(&app, Some("full")).await;
    let origin = unique_origin();
    let secret_key = Keys::generate().secret_key().to_bech32().unwrap();

    for body in [
        json!({ "origin": origin, "merchant_name": "Shop" }),
        json!({ "origin": origin, "merchant_name": "Shop", "merchant_pubkey": "" }),
        json!({ "origin": origin, "merchant_name": "Shop", "merchant_pubkey": "not-a-key" }),
        json!({ "origin": origin, "merchant_name": "Shop", "merchant_pubkey": "abcd" }),
        json!({ "origin": origin, "merchant_name": "Shop", "merchant_pubkey": secret_key }),
    ] {
        let refused = request(
            &app,
            Method::POST,
            OWNER_HOST,
            "/api/admin/customer-origins",
            Some(&admin),
            body.clone(),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{body}");
    }

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM customer_app_origins WHERE origin = $1")
            .bind(&origin)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(rows, 0, "Nothing was added");
}

#[tokio::test]
#[serial]
async fn test_merchant_key_given_as_npub_is_stored_as_hex() {
    let app = setup().await;
    let admin = admin_session(&app, Some("full")).await;
    let origin = unique_origin();
    let merchant = Keys::generate().public_key();

    let added = request(
        &app,
        Method::POST,
        OWNER_HOST,
        "/api/admin/customer-origins",
        Some(&admin),
        json!({
            "origin": origin,
            "merchant_name": "Shop",
            "merchant_pubkey": merchant.to_bech32().unwrap(),
        }),
    )
    .await;

    assert_eq!(added.status, StatusCode::OK, "{}", added.raw);
    assert_eq!(added.body["merchant_pubkey"], merchant.to_hex());
    let answer = sign_in_at(&app, &unique_email(), &origin, &merchant.to_hex()).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
}

/// Adding an origin again changes its merchant for new sign-ins; existing grants stay as they are.
#[tokio::test]
#[serial]
async fn test_adding_an_origin_again_changes_its_merchant_for_new_sign_ins() {
    let app = setup().await;
    let origin = unique_origin();
    let old_merchant = add_merchant(&app, &origin, "Shop").await;
    let session = session_of(&sign_in_at(&app, &unique_email(), &origin, &old_merchant).await);

    let new_merchant = add_merchant(&app, &origin, "Shop").await;

    let refused = sign_in_at(&app, &unique_email(), &origin, &old_merchant).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.raw);
    let granted = sign_in_at(&app, &unique_email(), &origin, &new_merchant).await;
    assert_eq!(granted.status, StatusCode::OK, "{}", granted.raw);
    assert_eq!(rpc_status(&app, &session).await, StatusCode::OK);
}
