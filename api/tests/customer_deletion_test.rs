#![cfg(feature = "integration-tests")]

// ABOUTME: Tests that a customer deletes their account through a fresh email link
// ABOUTME: and that Synvya Server is told once, with a signed notice, retried until acknowledged

mod common;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::customer_deletion::deliver_due_notices;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::{
    CustomerAppOriginRepository, MagicLinkTokenRepository, PURPOSE_DELETE_ACCOUNT, PURPOSE_SIGN_IN,
};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{Event, Keys, Kind};
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const CUSTOMER_HOST: &str = "customers.deletion.example.com";
const OWNER_HOST: &str = "owners.deletion.example.com";
const APP_URL: &str = "https://orders.example.com/account";

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
    let secret_pool = SecretPool::new(1);
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
    CustomerAppOriginRepository::new(pool.clone())
        .add(
            customer_tenant,
            "https://orders.example.com",
            "Example Shop",
        )
        .await
        .unwrap();
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

async fn new_link(app: &TestApp, email: &str, purpose: &str) -> String {
    let token = Uuid::new_v4().to_string();
    MagicLinkTokenRepository::new(app.pool.clone())
        .create(
            app.customer_tenant,
            email,
            &token,
            purpose,
            APP_URL,
            Utc::now() + Duration::minutes(15),
            None,
        )
        .await
        .unwrap();
    token
}

async fn verify(app: &TestApp, token: &str) -> Answer {
    request(
        app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({ "token": token }),
    )
    .await
}

/// Sign a new customer in. Returns (email, pubkey, ordinary session).
async fn signed_in_customer(app: &TestApp) -> (String, String, String) {
    let email = format!("customer-{}@example.com", Uuid::new_v4());
    let token = new_link(app, &email, PURPOSE_SIGN_IN).await;
    let answer = verify(app, &token).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);

    let pubkey: String = sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    (
        email,
        pubkey,
        answer.body["session_token"].as_str().unwrap().to_string(),
    )
}

async fn delete_account(app: &TestApp, session: &str) -> Answer {
    request(
        app,
        Method::DELETE,
        CUSTOMER_HOST,
        "/api/customer/account",
        Some(session),
        Value::Null,
    )
    .await
}

async fn notice_count(app: &TestApp, pubkey: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM customer_deletion_notices WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

async fn user_count(app: &TestApp, pubkey: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE pubkey = $1")
        .bind(pubkey)
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn test_ordinary_session_cannot_delete() {
    let app = setup().await;
    let (_, pubkey, session) = signed_in_customer(&app).await;

    let answer = delete_account(&app, &session).await;

    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.raw);
    assert_eq!(user_count(&app, &pubkey).await, 1);
    assert_eq!(notice_count(&app, &pubkey).await, 0);
}

#[tokio::test]
#[serial]
async fn test_deletion_link_deletes_the_account_and_records_a_notice() {
    let app = setup().await;
    let (email, pubkey, _) = signed_in_customer(&app).await;

    let token = new_link(&app, &email, PURPOSE_DELETE_ACCOUNT).await;
    let answer = verify(&app, &token).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert_eq!(answer.body["expires_in"], 600);
    assert!(!answer.raw.contains(&pubkey), "Never returns the pubkey");
    let session = answer.body["session_token"].as_str().unwrap();

    let deleted = delete_account(&app, session).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.raw);
    assert!(!deleted.raw.contains(&pubkey));

    assert_eq!(user_count(&app, &pubkey).await, 0);
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM personal_keys WHERE user_pubkey = $1")
        .bind(&pubkey)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(keys, 0, "The key goes with the account");
    assert_eq!(notice_count(&app, &pubkey).await, 1);

    let _ = sqlx::query("DELETE FROM customer_deletion_notices WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&app.pool)
        .await;
}

#[tokio::test]
#[serial]
async fn test_deletion_removes_links_still_in_the_inbox() {
    let app = setup().await;
    let (email, pubkey, _) = signed_in_customer(&app).await;
    let unused_sign_in = new_link(&app, &email, PURPOSE_SIGN_IN).await;

    let token = new_link(&app, &email, PURPOSE_DELETE_ACCOUNT).await;
    let session = verify(&app, &token).await.body["session_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(delete_account(&app, &session).await.status, StatusCode::OK);

    assert_eq!(
        verify(&app, &unused_sign_in).await.status,
        StatusCode::BAD_REQUEST,
        "An old link must not bring the account back"
    );

    let _ = sqlx::query("DELETE FROM customer_deletion_notices WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&app.pool)
        .await;
}

#[tokio::test]
#[serial]
async fn test_deletion_link_needs_a_signed_in_customer() {
    let app = setup().await;

    let signed_out = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link",
        None,
        json!({ "app_url": APP_URL, "purpose": "delete_account" }),
    )
    .await;
    assert_eq!(
        signed_out.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        signed_out.raw
    );

    let (email, _, session) = signed_in_customer(&app).await;
    let signed_in = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link",
        Some(&session),
        // Even naming someone else, it can only go to the customer's own address
        json!({ "email": "someone-else@example.com", "app_url": APP_URL, "purpose": "delete_account" }),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.raw);

    let mut rows = 0_i64;
    for _ in 0..50 {
        rows = sqlx::query_scalar(
            "SELECT COUNT(*) FROM magic_link_tokens WHERE email = $1 AND purpose = 'delete_account'",
        )
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
        if rows > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(rows, 1);
    let to_someone_else: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM magic_link_tokens WHERE email = 'someone-else@example.com'",
    )
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(to_someone_else, 0);
}

#[tokio::test]
#[serial]
async fn test_invalid_purpose_is_refused() {
    let app = setup().await;

    let answer = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link",
        None,
        json!({ "email": "a@example.com", "app_url": APP_URL, "purpose": "other" }),
    )
    .await;

    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn test_customer_route_does_not_exist_on_other_hostnames() {
    let app = setup().await;

    let answer = request(
        &app,
        Method::DELETE,
        OWNER_HOST,
        "/api/customer/account",
        Some("anything"),
        Value::Null,
    )
    .await;

    assert_eq!(answer.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial]
async fn test_owner_deletion_records_no_notice() {
    let app = setup().await;
    let keys = Keys::generate();
    let pubkey = keys.public_key().to_hex();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(app.owner_tenant)
    .bind(format!("{}@example.com", &pubkey[..16]))
    .execute(&app.pool)
    .await
    .unwrap();
    let session = keycast_api::api::http::auth::generate_server_signed_ucan(
        &keys.public_key(),
        app.owner_tenant,
        "owner@example.com",
        "https://account.example.com",
        None,
        &app.server_keys,
        true,
        None,
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap();

    let answer = request(
        &app,
        Method::DELETE,
        OWNER_HOST,
        "/api/user/account",
        Some(&session),
        Value::Null,
    )
    .await;

    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert_eq!(user_count(&app, &pubkey).await, 0);
    assert_eq!(notice_count(&app, &pubkey).await, 0);
}

// ----------------------------------------------------------------------------
// Delivering the notice
// ----------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockServer {
    received: Arc<Mutex<Vec<(HeaderMap, Bytes)>>>,
    failures_left: Arc<AtomicUsize>,
}

async fn receive_notice(
    State(server): State<MockServer>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    server.received.lock().unwrap().push((headers, body));
    if server.failures_left.load(Ordering::SeqCst) > 0 {
        server.failures_left.fetch_sub(1, Ordering::SeqCst);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}

async fn start_mock_server(failures: usize) -> (MockServer, String) {
    let server = MockServer::default();
    server.failures_left.store(failures, Ordering::SeqCst);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/notices", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/notices", post(receive_notice))
        .with_state(server.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (server, url)
}

async fn record_notice(app: &TestApp) -> String {
    let pubkey = Keys::generate().public_key().to_hex();
    sqlx::query("INSERT INTO customer_deletion_notices (tenant_id, pubkey) VALUES ($1, $2)")
        .bind(app.customer_tenant)
        .bind(&pubkey)
        .execute(&app.pool)
        .await
        .unwrap();
    pubkey
}

fn tag_value(event: &Event, name: &str) -> String {
    event
        .tags
        .iter()
        .find_map(|tag| {
            let tag = tag.as_slice();
            (tag.first().map(String::as_str) == Some(name)).then(|| tag[1].clone())
        })
        .unwrap_or_else(|| panic!("Missing tag {name}"))
}

#[tokio::test]
#[serial]
async fn test_notice_is_signed_retried_and_sent_once_acknowledged() {
    let app = setup().await;
    let client = reqwest::Client::new();
    let (server, url) = start_mock_server(1).await;

    // Only this test's notice, so the count below is exact
    sqlx::query("DELETE FROM customer_deletion_notices")
        .execute(&app.pool)
        .await
        .unwrap();
    let pubkey = record_notice(&app).await;

    // The first attempt fails, and the notice stays
    assert_eq!(
        deliver_due_notices(&app.pool, &client, &app.server_keys, &url)
            .await
            .unwrap(),
        0
    );
    assert_eq!(notice_count(&app, &pubkey).await, 1);

    // It is not due again straight away
    assert_eq!(
        deliver_due_notices(&app.pool, &client, &app.server_keys, &url)
            .await
            .unwrap(),
        0
    );
    assert_eq!(server.received.lock().unwrap().len(), 1);

    // When it comes due, it is delivered and acknowledged
    sqlx::query("UPDATE customer_deletion_notices SET next_attempt_at = NOW() WHERE pubkey = $1")
        .bind(&pubkey)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        deliver_due_notices(&app.pool, &client, &app.server_keys, &url)
            .await
            .unwrap(),
        1
    );
    assert_eq!(notice_count(&app, &pubkey).await, 0);

    // And it is never sent again
    deliver_due_notices(&app.pool, &client, &app.server_keys, &url)
        .await
        .unwrap();
    let received = server.received.lock().unwrap();
    assert_eq!(received.len(), 2, "One failure, then one acknowledged");

    let (headers, body) = received.last().unwrap();
    let notice: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(notice["pubkey"], pubkey);

    let authorization = headers
        .get(header::AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap();
    let encoded = authorization
        .strip_prefix("Nostr ")
        .expect("A NIP-98 header");
    let event: Event = serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
    event.verify().expect("A valid signature");
    assert_eq!(event.kind, Kind::HttpAuth);
    assert_eq!(
        event.pubkey,
        app.server_keys.public_key(),
        "Signed with the server key"
    );
    assert_eq!(tag_value(&event, "u"), url);
    assert_eq!(tag_value(&event, "method"), "POST");
    assert_eq!(
        tag_value(&event, "payload"),
        hex::encode(Sha256::digest(body))
    );
}
