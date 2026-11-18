#![cfg(feature = "integration-tests")]

// ABOUTME: Tests for POST /api/user/staff-challenge/sign (Synvya)
// ABOUTME: The person's key signs the staff challenge only for a session from a listed origin

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::Utc;
use http_body_util::BodyExt;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{Event, Keys};
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const OWNER_HOST: &str = "owners.staff-challenge.example.com";
const LISTED: &str = "https://account.example.com";
const UNLISTED: &str = "https://admin.example.com";

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
    tenant: i64,
    server_keys: Keys,
}

async fn setup() -> TestApp {
    let pool = common::setup_test_db().await;
    // Read once per process by StaffChallengeOrigins::current(); this file is its own process.
    std::env::set_var("STAFF_CHALLENGE_ORIGINS", LISTED);
    if std::env::var("SERVER_NSEC").is_err() {
        std::env::set_var("SERVER_NSEC", "0".repeat(63) + "1");
    }
    let server_keys = Keys::parse(&std::env::var("SERVER_NSEC").unwrap()).unwrap();
    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.com");

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

    let owner = sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $1, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(OWNER_HOST)
    .fetch_one(&pool)
    .await
    .expect("tenant");
    let tenant = owner.id;
    get_tenant_cache()
        .unwrap()
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
        tenant,
        server_keys,
    }
}

/// A person with a personal key and no authorization for any origin.
async fn person(app: &TestApp) -> (Keys, String) {
    let keys = Keys::generate();
    let email = format!("staff-{}@example.com", Uuid::new_v4());
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, $4, $4)",
    )
    .bind(keys.public_key().to_hex())
    .bind(app.tenant)
    .bind(&email)
    .bind(now)
    .execute(&app.pool)
    .await
    .expect("user");
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $4)",
    )
    .bind(keys.public_key().to_hex())
    .bind(keys.secret_key().secret_bytes().to_vec())
    .bind(app.tenant)
    .bind(now)
    .execute(&app.pool)
    .await
    .expect("personal key");
    (keys, email)
}

async fn session(app: &TestApp, keys: &Keys, email: &str, origin: &str) -> String {
    generate_server_signed_ucan(
        &keys.public_key(),
        app.tenant,
        email,
        origin,
        None,
        &app.server_keys,
        true,
        None,
    )
    .await
    .unwrap()
}

async fn sign(app: &TestApp, token: &str, body: Value) -> (StatusCode, Value) {
    let res = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/user/staff-challenge/sign")
                .header(header::HOST, OWNER_HOST)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, format!("keycast_session={token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn challenge() -> Value {
    json!({ "challenge_id": "c-1", "nonce": "n-1", "expires_at": "2026-11-18T20:00:00.000Z" })
}

#[tokio::test]
#[serial]
async fn signs_the_four_tag_challenge_for_a_listed_origin() {
    let app = setup().await;
    let (keys, email) = person(&app).await;
    let token = session(&app, &keys, &email, LISTED).await;
    let (status, body) = sign(&app, &token, challenge()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let event: Event = serde_json::from_value(body["signed_event"].clone()).unwrap();
    event.verify().expect("signature");
    assert_eq!(event.pubkey, keys.public_key());
    assert_eq!(event.kind.as_u16(), 27235);
    let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.clone().to_vec()).collect();
    assert_eq!(
        tags,
        vec![
            vec!["challenge_id".to_string(), "c-1".to_string()],
            vec!["nonce".to_string(), "n-1".to_string()],
            vec!["person_pubkey".to_string(), keys.public_key().to_hex()],
            vec![
                "expires_at".to_string(),
                "2026-11-18T20:00:00.000Z".to_string()
            ],
        ]
    );
}

#[tokio::test]
#[serial]
async fn refuses_a_session_from_an_origin_not_listed() {
    let app = setup().await;
    let (keys, email) = person(&app).await;
    let token = session(&app, &keys, &email, UNLISTED).await;
    let (status, _) = sign(&app, &token, challenge()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn refuses_a_bad_value_and_a_missing_session() {
    let app = setup().await;
    let (keys, email) = person(&app).await;
    let token = session(&app, &keys, &email, LISTED).await;
    let (status, _) = sign(
        &app,
        &token,
        json!({ "challenge_id": "c 1", "nonce": "n-1", "expires_at": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = sign(&app, "not-a-token", challenge()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
