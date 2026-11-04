#![cfg(feature = "integration-tests")]

// ABOUTME: Tests that a session only works on the hostname of its own tenant
// ABOUTME: Drives the real routes with real Host headers, for sessions, cookies and /api/nostr

mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::{ensure_customer_tenant, Tenant};
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_api::ucan_auth::{nostr_pubkey_to_did, NostrKeyMaterial};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::Keys;
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use ucan::builder::UcanBuilder;
use zeroize::Zeroizing;

const OWNER_HOST: &str = "owners.tenant-isolation.example.com";
const CUSTOMER_HOST: &str = "customers.tenant-isolation.example.com";

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
    owner_tenant: i64,
    customer_tenant: i64,
}

fn server_keys_from_env() -> Keys {
    if std::env::var("SERVER_NSEC").is_err() {
        std::env::set_var("SERVER_NSEC", "0".repeat(63) + "1");
    }
    Keys::parse(&std::env::var("SERVER_NSEC").unwrap()).expect("SERVER_NSEC must be valid")
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
    let server_keys = server_keys_from_env();
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

    // TenantExtractor reads the global cache; only that part of the global state is used here,
    // because every hostname in these tests is already in the cache
    let _ = KEYCAST_STATE.set(state.clone());

    let owner = upsert_tenant(&pool, OWNER_HOST).await;
    let customer = upsert_tenant(&pool, CUSTOMER_HOST).await;
    let (owner_tenant, customer_tenant) = (owner.id, customer.id);
    let tenant_cache = get_tenant_cache().unwrap();
    tenant_cache
        .insert(OWNER_HOST.to_string(), Arc::new(owner))
        .await;
    tenant_cache
        .insert(CUSTOMER_HOST.to_string(), Arc::new(customer))
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
        owner_tenant,
        customer_tenant,
    }
}

/// A user with an email, a key and one authorization in a tenant; returns the bunker pubkey.
async fn create_user(pool: &PgPool, tenant_id: i64, keys: &Keys) -> String {
    let pubkey = keys.public_key().to_hex();
    let bunker = Keys::generate().public_key().to_hex();

    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, email_verified, created_at, updated_at)
         VALUES ($1, $2, $3, true, NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(tenant_id)
    .bind(format!("{}@example.com", &pubkey[..16]))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO personal_keys (user_pubkey, encrypted_secret_key, tenant_id)
         VALUES ($1, $2, $3)",
    )
    .bind(&pubkey)
    .bind(keys.secret_key().secret_bytes().to_vec())
    .bind(tenant_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_pubkey, redirect_origin, bunker_public_key, secret_hash, relays, tenant_id,
          authorization_handle, handle_expires_at, created_at, updated_at)
         VALUES ($1, 'https://orders.example.com', $2, 'test_hash', '[]', $3, $4,
                 NOW() + INTERVAL '30 days', NOW(), NOW())",
    )
    .bind(&pubkey)
    .bind(&bunker)
    .bind(tenant_id)
    .bind(hex::encode(rand::random::<[u8; 32]>()))
    .execute(pool)
    .await
    .unwrap();

    bunker
}

async fn delete_user(pool: &PgPool, keys: &Keys) {
    let pubkey = keys.public_key().to_hex();
    for query in [
        "DELETE FROM oauth_authorizations WHERE user_pubkey = $1",
        "DELETE FROM personal_keys WHERE user_pubkey = $1",
        "DELETE FROM users WHERE pubkey = $1",
    ] {
        let _ = sqlx::query(query).bind(&pubkey).execute(pool).await;
    }
}

async fn session_token(app: &TestApp, keys: &Keys, tenant_id: i64, bunker: Option<&str>) -> String {
    generate_server_signed_ucan(
        &keys.public_key(),
        tenant_id,
        "user@example.com",
        "https://orders.example.com",
        bunker,
        &app.server_keys,
        false,
        None,
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap()
}

async fn get(app: &TestApp, host: &str, path: &str, token: &str) -> StatusCode {
    let request = Request::builder()
        .uri(path)
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.router.clone().oneshot(request).await.unwrap().status()
}

async fn get_with_cookie(app: &TestApp, host: &str, path: &str, token: &str) -> StatusCode {
    let request = Request::builder()
        .uri(path)
        .header(header::HOST, host)
        .header(header::COOKIE, format!("keycast_session={token}"))
        .body(Body::empty())
        .unwrap();
    app.router.clone().oneshot(request).await.unwrap().status()
}

async fn rpc_get_public_key(app: &TestApp, host: &str, token: &str) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri("/api/nostr")
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"method":"get_public_key","params":[]}"#))
        .unwrap();
    app.router.clone().oneshot(request).await.unwrap().status()
}

// `/user/profile` uses extract_user_from_token, `/teams` uses the UcanAuth extractor.
const SESSION_ROUTES: [&str; 2] = ["/api/user/profile", "/api/teams"];

#[tokio::test]
async fn test_owner_session_is_refused_on_the_customer_hostname() {
    let app = setup().await;
    let keys = Keys::generate();
    create_user(&app.pool, app.owner_tenant, &keys).await;
    let token = session_token(&app, &keys, app.owner_tenant, None).await;

    for path in SESSION_ROUTES {
        assert_ne!(
            get(&app, OWNER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should accept the session on its own hostname"
        );
        assert_eq!(
            get(&app, CUSTOMER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should refuse the session on the customer hostname"
        );
    }

    delete_user(&app.pool, &keys).await;
}

#[tokio::test]
async fn test_customer_session_is_refused_on_the_owner_hostname() {
    let app = setup().await;
    let keys = Keys::generate();
    create_user(&app.pool, app.customer_tenant, &keys).await;
    let token = session_token(&app, &keys, app.customer_tenant, None).await;

    for path in SESSION_ROUTES {
        assert_ne!(
            get(&app, CUSTOMER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should accept the session on its own hostname"
        );
        assert_eq!(
            get(&app, OWNER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should refuse the session on the owner hostname"
        );
    }

    delete_user(&app.pool, &keys).await;
}

#[tokio::test]
async fn test_session_cookie_is_refused_on_another_hostname() {
    let app = setup().await;
    let keys = Keys::generate();
    create_user(&app.pool, app.owner_tenant, &keys).await;
    let token = session_token(&app, &keys, app.owner_tenant, None).await;

    for path in SESSION_ROUTES {
        assert_ne!(
            get_with_cookie(&app, OWNER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should accept the cookie on its own hostname"
        );
        assert_eq!(
            get_with_cookie(&app, CUSTOMER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should refuse the cookie on another hostname"
        );
    }

    delete_user(&app.pool, &keys).await;
}

#[tokio::test]
async fn test_session_without_a_tenant_is_refused() {
    let app = setup().await;
    let keys = Keys::generate();
    create_user(&app.pool, app.owner_tenant, &keys).await;

    let token = UcanBuilder::default()
        .issued_by(&NostrKeyMaterial::from_keys(keys.clone()))
        .for_audience(&nostr_pubkey_to_did(&keys.public_key()))
        .with_lifetime(600)
        .with_fact(serde_json::json!({ "redirect_origin": "https://orders.example.com" }))
        .build()
        .unwrap()
        .sign()
        .await
        .unwrap()
        .encode()
        .unwrap();

    for path in SESSION_ROUTES {
        assert_eq!(
            get(&app, OWNER_HOST, path, &token).await,
            StatusCode::UNAUTHORIZED,
            "{path} should refuse a session with no tenant"
        );
    }

    delete_user(&app.pool, &keys).await;
}

/// A cache hit on /api/nostr skips the session checks, so the second call is the one that matters.
#[tokio::test]
async fn test_nostr_rpc_token_is_refused_on_another_hostname_after_a_cache_hit() {
    let app = setup().await;
    let keys = Keys::generate();
    let bunker = create_user(&app.pool, app.customer_tenant, &keys).await;
    let token = session_token(&app, &keys, app.customer_tenant, Some(&bunker)).await;

    assert_eq!(
        rpc_get_public_key(&app, CUSTOMER_HOST, &token).await,
        StatusCode::OK
    );
    assert_eq!(
        rpc_get_public_key(&app, CUSTOMER_HOST, &token).await,
        StatusCode::OK,
        "The second call on the same hostname should hit the cache and still work"
    );
    assert_eq!(
        rpc_get_public_key(&app, OWNER_HOST, &token).await,
        StatusCode::UNAUTHORIZED
    );

    delete_user(&app.pool, &keys).await;
}

#[tokio::test]
#[serial]
async fn test_customer_tenant_is_created_from_its_domain() {
    let pool = common::setup_test_db().await;
    let domain = format!("customers-{}.example.com", uuid::Uuid::new_v4());

    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.com");
    std::env::set_var("CUSTOMER_TENANT_DOMAIN", &domain);
    let first = ensure_customer_tenant(&pool).await.unwrap().unwrap();
    let second = ensure_customer_tenant(&pool).await.unwrap().unwrap();
    let is_customer_tenant = first.is_customer_tenant();

    std::env::remove_var("CUSTOMER_TENANT_DOMAIN");
    let when_unset = ensure_customer_tenant(&pool).await.unwrap();
    std::env::remove_var("BUNKER_RELAYS");

    assert_eq!(first.id, second.id, "Creating it twice should be a no-op");
    assert_eq!(first.domain, domain);
    assert!(is_customer_tenant);
    assert!(when_unset.is_none());

    let _ = sqlx::query("DELETE FROM tenants WHERE domain = $1")
        .bind(&domain)
        .execute(&pool)
        .await;
}
