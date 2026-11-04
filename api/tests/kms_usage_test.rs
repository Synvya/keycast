#![cfg(feature = "integration-tests")]

// ABOUTME: Counts key manager calls for 100 sign-ins followed by 100 signatures, before and after
// ABOUTME: the decrypted key cache, through the real routes. Each call is a paid KMS call in production

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::caching_key_manager::CachingKeyManager;
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::{
    CustomerAppOriginRepository, MagicLinkTokenRepository, PURPOSE_SIGN_IN,
};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{EventBuilder, Keys, Kind, PublicKey};
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const CUSTOMER_HOST: &str = "customers.kms-usage.example.com";
const APP_URL: &str = "https://orders.example.com/signin";
const COUNT: usize = 100;

#[derive(Default)]
struct Calls {
    encrypts: AtomicUsize,
    decrypts: AtomicUsize,
}

/// Stands in for KMS and counts the calls that would reach it.
struct CountingKeyManager(Arc<Calls>);

#[async_trait::async_trait]
impl KeyManager for CountingKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        self.0.encrypts.fetch_add(1, Ordering::SeqCst);
        Ok(plaintext_bytes.to_vec())
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        self.0.decrypts.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(ciphertext_bytes.to_vec()))
    }
}

struct TestApp {
    pool: PgPool,
    router: Router,
    tenant_id: i64,
    calls: Arc<Calls>,
}

async fn setup(cached: bool) -> TestApp {
    let pool = common::setup_test_db().await;

    if std::env::var("SERVER_NSEC").is_err() {
        std::env::set_var("SERVER_NSEC", "0".repeat(63) + "1");
    }
    let server_keys = Keys::parse(&std::env::var("SERVER_NSEC").unwrap()).unwrap();
    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.com");
    std::env::set_var("CUSTOMER_TENANT_DOMAIN", CUSTOMER_HOST);

    let calls = Arc::new(Calls::default());
    let counting: Box<dyn KeyManager> = Box::new(CountingKeyManager(calls.clone()));
    let key_manager: Box<dyn KeyManager> = if cached {
        Box::new(CachingKeyManager::new(counting))
    } else {
        counting
    };

    let bcrypt_queue = BcryptQueue::new();
    let secret_pool = SecretPool::new(16);
    secret_pool.spawn_producer();
    let state = Arc::new(KeycastState {
        db: pool.clone(),
        key_manager: Arc::new(key_manager),
        signer_handlers: None,
        http_handler_cache: new_http_handler_cache(),
        server_keys,
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt_sender: bcrypt_queue.sender(),
        redis: None,
        secret_pool: secret_pool.receiver(),
        secure_cookies: false,
    });
    // The global state outlives each scenario, so it must not keep a producer alive: a producer
    // blocked on a full pool would stop the test's runtime from shutting down
    let idle_pool = SecretPool::new(1);
    let _ = KEYCAST_STATE.set(Arc::new(KeycastState {
        db: pool.clone(),
        key_manager: Arc::new(Box::new(CountingKeyManager(Arc::new(Calls::default())))),
        signer_handlers: None,
        http_handler_cache: new_http_handler_cache(),
        server_keys: state.server_keys.clone(),
        tenant_cache: Cache::builder().max_capacity(10).build(),
        bcrypt_sender: bcrypt_queue.sender(),
        redis: None,
        secret_pool: idle_pool.receiver(),
        secure_cookies: false,
    }));

    let tenant = sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $1, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(CUSTOMER_HOST)
    .fetch_one(&pool)
    .await
    .unwrap();
    let tenant_id = tenant.id;
    get_tenant_cache()
        .unwrap()
        .insert(CUSTOMER_HOST.to_string(), Arc::new(tenant))
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
        tenant_id,
        calls,
    }
}

async fn post(app: &TestApp, path: &str, bearer: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, CUSTOMER_HOST)
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Put the app on the approved list. Returns its merchant's key in hex.
async fn approve_merchant(app: &TestApp) -> String {
    let merchant = Keys::generate().public_key().to_hex();
    CustomerAppOriginRepository::new(app.pool.clone())
        .add(
            app.tenant_id,
            "https://orders.example.com",
            "Example Shop",
            &merchant,
        )
        .await
        .unwrap();
    merchant
}

/// One sign-in that grants the app the permission. Returns the session.
async fn sign_in(app: &TestApp, email: &str, merchant: &str) -> String {
    let token = Uuid::new_v4().to_string();
    MagicLinkTokenRepository::new(app.pool.clone())
        .create(
            app.tenant_id,
            email,
            &token,
            PURPOSE_SIGN_IN,
            APP_URL,
            Utc::now() + Duration::minutes(15),
            None,
        )
        .await
        .unwrap();
    let (status, body) = post(
        app,
        "/api/auth/magic-link/verify",
        None,
        json!({
            "token": token,
            "client_id": "orders.example.com",
            "redirect_uri": APP_URL,
            "scope": "policy:commerce_envelope",
            "merchant_pubkey": merchant,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["session_token"].as_str().unwrap().to_string()
}

/// One signature: the kind 13 seal around an order.
async fn sign(app: &TestApp, session: &str, email: &str) {
    let pubkey_hex: String = sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    let seal = EventBuilder::new(Kind::from(13), "sealed")
        .build(PublicKey::from_hex(&pubkey_hex).unwrap());
    let (status, body) = post(
        app,
        "/api/nostr",
        Some(session),
        json!({ "method": "sign_event", "params": [seal] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn email() -> String {
    format!("customer-{}@example.com", Uuid::new_v4())
}

/// 100 new customers each sign in once and sign once. Returns (encrypts, decrypts).
async fn new_customers(cached: bool) -> (usize, usize) {
    let app = setup(cached).await;
    let merchant = approve_merchant(&app).await;

    let mut customers = Vec::new();
    for _ in 0..COUNT {
        let email = email();
        let session = sign_in(&app, &email, &merchant).await;
        customers.push((email, session));
    }
    for (email, session) in &customers {
        sign(&app, session, email).await;
    }

    (
        app.calls.encrypts.load(Ordering::SeqCst),
        app.calls.decrypts.load(Ordering::SeqCst),
    )
}

/// One customer signs in 100 times and signs with each session. Returns (encrypts, decrypts).
async fn returning_customer(cached: bool) -> (usize, usize) {
    let app = setup(cached).await;
    let merchant = approve_merchant(&app).await;
    let email = email();

    let mut sessions = Vec::new();
    for _ in 0..COUNT {
        sessions.push(sign_in(&app, &email, &merchant).await);
    }
    for session in &sessions {
        sign(&app, session, &email).await;
    }

    (
        app.calls.encrypts.load(Ordering::SeqCst),
        app.calls.decrypts.load(Ordering::SeqCst),
    )
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_kms_calls_for_100_sign_ins_and_100_signatures() {
    let new_before = new_customers(false).await;
    let new_after = new_customers(true).await;
    let returning_before = returning_customer(false).await;
    let returning_after = returning_customer(true).await;

    println!("KMS calls (encrypt, decrypt) for {COUNT} sign-ins then {COUNT} signatures");
    println!("  new customers:      before {new_before:?}, after {new_after:?}");
    println!("  returning customer: before {returning_before:?}, after {returning_after:?}");

    assert_eq!(new_before, (COUNT, 2 * COUNT));
    assert_eq!(new_after, (COUNT, 0));
    assert_eq!(returning_before, (1, 2 * COUNT));
    assert_eq!(returning_after, (1, 0));
}
