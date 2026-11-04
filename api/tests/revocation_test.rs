#![cfg(feature = "integration-tests")]

// ABOUTME: Tests that revoking an authorization takes effect on the app's next call
// ABOUTME: Covers the /api/nostr handler cache and the lookups that ignored revoked rows

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::OAuthAuthorizationRepository;
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::Keys;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use zeroize::Zeroizing;

const HOST: &str = "owners.revocation.example.com";
const ORIGIN: &str = "https://orders.example.com";

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
    tenant_id: i64,
}

async fn setup() -> TestApp {
    let pool = common::setup_test_db().await;

    if std::env::var("SERVER_NSEC").is_err() {
        std::env::set_var("SERVER_NSEC", "0".repeat(63) + "1");
    }
    let server_keys = Keys::parse(&std::env::var("SERVER_NSEC").unwrap()).unwrap();

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

    let tenant = sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, created_at, updated_at)
         VALUES ($1, $1, NOW(), NOW())
         ON CONFLICT (domain) DO UPDATE SET updated_at = tenants.updated_at
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(HOST)
    .fetch_one(&pool)
    .await
    .unwrap();
    let tenant_id = tenant.id;
    get_tenant_cache()
        .unwrap()
        .insert(HOST.to_string(), Arc::new(tenant))
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
        tenant_id,
    }
}

async fn create_user(app: &TestApp, keys: &Keys) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(keys.public_key().to_hex())
    .bind(app.tenant_id)
    .bind(format!("{}@example.com", &keys.public_key().to_hex()[..16]))
    .execute(&app.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(keys.public_key().to_hex())
    .bind(keys.secret_key().secret_bytes().to_vec())
    .bind(app.tenant_id)
    .execute(&app.pool)
    .await
    .unwrap();
}

/// Returns the new authorization's bunker pubkey.
async fn create_authorization(app: &TestApp, keys: &Keys, origin: &str) -> String {
    let bunker = Keys::generate().public_key().to_hex();
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, tenant_id,
          authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, $2, $3, 'test_hash', '[]', $4, $5, NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(keys.public_key().to_hex())
    .bind(origin)
    .bind(&bunker)
    .bind(app.tenant_id)
    .bind(hex::encode(rand::random::<[u8; 32]>()))
    .execute(&app.pool)
    .await
    .unwrap();
    bunker
}

async fn token_for(app: &TestApp, keys: &Keys, origin: &str, bunker: &str) -> String {
    generate_server_signed_ucan(
        &keys.public_key(),
        app.tenant_id,
        "user@example.com",
        origin,
        Some(bunker),
        &app.server_keys,
        false,
        None,
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap()
}

async fn post(app: &TestApp, path: &str, token: &str, body: Value) -> StatusCode {
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    app.router.clone().oneshot(request).await.unwrap().status()
}

async fn rpc(app: &TestApp, token: &str) -> StatusCode {
    post(
        app,
        "/api/nostr",
        token,
        json!({ "method": "get_public_key", "params": [] }),
    )
    .await
}

#[tokio::test]
async fn test_revoked_app_fails_on_its_next_call_and_others_keep_working() {
    let app = setup().await;
    let keys = Keys::generate();
    create_user(&app, &keys).await;

    let revoked_bunker = create_authorization(&app, &keys, ORIGIN).await;
    let other_bunker = create_authorization(&app, &keys, "https://orders.example.org").await;
    let revoked_token = token_for(&app, &keys, ORIGIN, &revoked_bunker).await;
    let other_token = token_for(&app, &keys, "https://orders.example.org", &other_bunker).await;

    // Both handlers are cached after these calls
    for token in [&revoked_token, &other_token] {
        assert_eq!(rpc(&app, token).await, StatusCode::OK);
        assert_eq!(rpc(&app, token).await, StatusCode::OK);
    }

    assert_eq!(
        post(
            &app,
            "/api/user/sessions/revoke",
            &other_token,
            json!({ "bunker_pubkey": revoked_bunker })
        )
        .await,
        StatusCode::OK
    );

    assert_eq!(rpc(&app, &revoked_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        rpc(&app, &other_token).await,
        StatusCode::OK,
        "Another authorization is not affected"
    );
}

#[tokio::test]
async fn test_lookups_skip_revoked_authorizations() {
    let app = setup().await;
    let keys = Keys::generate();
    create_user(&app, &keys).await;
    let pubkey = keys.public_key().to_hex();
    let repo = OAuthAuthorizationRepository::new(app.pool.clone());

    let first = create_authorization(&app, &keys, ORIGIN).await;
    assert_eq!(
        repo.find_latest_bunker_pubkey(&pubkey, app.tenant_id)
            .await
            .unwrap(),
        Some(first.clone())
    );
    assert!(repo
        .find_policy_id_by_origin(&pubkey, ORIGIN, app.tenant_id)
        .await
        .unwrap()
        .is_some());

    sqlx::query("UPDATE oauth_authorizations SET revoked_at = NOW() WHERE bunker_public_key = $1")
        .bind(&first)
        .execute(&app.pool)
        .await
        .unwrap();

    assert_eq!(
        repo.find_latest_bunker_pubkey(&pubkey, app.tenant_id)
            .await
            .unwrap(),
        None
    );
    assert!(repo
        .find_policy_id_by_origin(&pubkey, ORIGIN, app.tenant_id)
        .await
        .unwrap()
        .is_none());
}
