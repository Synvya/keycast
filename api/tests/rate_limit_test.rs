#![cfg(feature = "integration-tests")]

// ABOUTME: Tests that endpoints which send email or call KMS refuse at their limits
// ABOUTME: Each endpoint is driven through its real route, by email and by IP

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::rate_limit::{
    email_limit_key, ip_limit_key, once_per_window, under_limit, EMAIL_LIMIT_PER_HOUR,
};
use keycast_api::redis::PrefixedRedis;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::Keys;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const HOST: &str = "owners.rate-limit.example.com";
const IP_LIMIT: u64 = 8;

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

async fn send(
    router: &Router,
    path: &str,
    bearer: Option<&str>,
    ip: IpAddr,
    body: Value,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", ip.to_string());
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let status = router
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
        .status();
    // A body the route cannot read never reaches the limits, so it would prove nothing
    assert_ne!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}");
    status
}

fn unique_email() -> String {
    format!("limits-{}@example.com", Uuid::new_v4())
}

fn unique_ip() -> IpAddr {
    let bytes: [u8; 4] = rand::random();
    IpAddr::from([100, bytes[1], bytes[2], bytes[3]])
}

struct Endpoint {
    route: &'static str,
    path: String,
    bearer: Option<String>,
    body: fn(&str) -> Value,
}

/// One test, because the global state keeps the Redis connection of the first runtime.
#[tokio::test]
async fn test_each_endpoint_refuses_at_its_limits_and_accepts_after_the_window() {
    let pool = common::setup_test_db().await;
    let redis = test_redis().await;

    if std::env::var("SERVER_NSEC").is_err() {
        std::env::set_var("SERVER_NSEC", "0".repeat(63) + "1");
    }
    std::env::set_var("BUNKER_RELAYS", "wss://relay.example.com");
    std::env::set_var("RATE_LIMIT_IP_PER_HOUR", IP_LIMIT.to_string());
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
        redis: Some(redis.clone()),
        secret_pool: secret_pool.receiver(),
        secure_cookies: false,
    });
    KEYCAST_STATE
        .set(state.clone())
        .map_err(|_| "already set")
        .unwrap();

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

    // An admin of a team, for the invitation route
    let admin = Keys::generate();
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())",
    )
    .bind(admin.public_key().to_hex())
    .bind(tenant_id)
    .execute(&pool)
    .await
    .unwrap();
    let team_id: i32 = sqlx::query_scalar(
        "INSERT INTO teams (tenant_id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW()) RETURNING id",
    )
    .bind(tenant_id)
    .bind(format!("Rate Limit Team {}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO team_users (team_id, user_pubkey, role, created_at, updated_at)
         VALUES ($1, $2, 'admin', NOW(), NOW())",
    )
    .bind(team_id)
    .bind(admin.public_key().to_hex())
    .execute(&pool)
    .await
    .unwrap();
    let admin_session = generate_server_signed_ucan(
        &admin.public_key(),
        tenant_id,
        "admin@example.com",
        "https://account.example.com",
        None,
        &server_keys,
        false,
        None,
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap();

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

    let register_body: fn(&str) -> Value =
        |email| json!({ "email": email, "password": "correct-horse-battery" });
    let app_register_body: fn(&str) -> Value = |email| {
        json!({
            "email": email,
            "password": "correct-horse-battery",
            "client_id": "Test App",
            "redirect_uri": "https://app.example.com/callback",
        })
    };
    let email_only_body: fn(&str) -> Value = |email| json!({ "email": email });

    let endpoints = [
        Endpoint {
            route: "register",
            path: "/api/auth/register".to_string(),
            bearer: None,
            body: register_body,
        },
        Endpoint {
            route: "headless_register",
            path: "/api/headless/register".to_string(),
            bearer: None,
            body: app_register_body,
        },
        Endpoint {
            route: "oauth_register",
            path: "/api/oauth/register".to_string(),
            bearer: None,
            body: app_register_body,
        },
        Endpoint {
            route: "forgot_password",
            path: "/api/auth/forgot-password".to_string(),
            bearer: None,
            body: email_only_body,
        },
        Endpoint {
            route: "resend_verification",
            path: "/api/auth/resend-verification".to_string(),
            bearer: None,
            body: email_only_body,
        },
        Endpoint {
            route: "team_invite",
            path: format!("/api/teams/{team_id}/invite"),
            bearer: Some(admin_session),
            body: |email| json!({ "email": email, "role": "Member" }),
        },
    ];

    for endpoint in &endpoints {
        let route = endpoint.route;
        let bearer = endpoint.bearer.as_deref();

        // By email, from a different address each time
        let email = unique_email();
        for attempt in 1..=EMAIL_LIMIT_PER_HOUR {
            let status = send(
                &router,
                &endpoint.path,
                bearer,
                unique_ip(),
                (endpoint.body)(&email),
            )
            .await;
            assert_ne!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "{route} email attempt {attempt}"
            );
        }
        assert_eq!(
            send(
                &router,
                &endpoint.path,
                bearer,
                unique_ip(),
                (endpoint.body)(&email)
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "{route} should refuse past the email limit"
        );
        redis
            .del(&email_limit_key(route, tenant_id, &email))
            .await
            .unwrap();
        assert_ne!(
            send(
                &router,
                &endpoint.path,
                bearer,
                unique_ip(),
                (endpoint.body)(&email)
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "{route} should accept the email again after the window"
        );

        // By IP, for a different email each time
        let ip = unique_ip();
        for attempt in 1..=IP_LIMIT {
            let status = send(
                &router,
                &endpoint.path,
                bearer,
                ip,
                (endpoint.body)(&unique_email()),
            )
            .await;
            assert_ne!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "{route} IP attempt {attempt}"
            );
        }
        assert_eq!(
            send(
                &router,
                &endpoint.path,
                bearer,
                ip,
                (endpoint.body)(&unique_email())
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "{route} should refuse past the IP limit"
        );
        redis
            .del(&ip_limit_key(route, tenant_id, ip))
            .await
            .unwrap();
        assert_ne!(
            send(
                &router,
                &endpoint.path,
                bearer,
                ip,
                (endpoint.body)(&unique_email())
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "{route} should accept the IP again after the window"
        );
    }

    std::env::remove_var("RATE_LIMIT_IP_PER_HOUR");
}

/// The windows above end by deleting the key. This one really runs out.
#[tokio::test]
async fn test_limits_reset_when_the_window_runs_out() {
    let redis = test_redis().await;

    assert!(under_limit(Some(&redis), "counted", 2, 1).await);
    assert!(under_limit(Some(&redis), "counted", 2, 1).await);
    assert!(!under_limit(Some(&redis), "counted", 2, 1).await);

    assert!(once_per_window(Some(&redis), "once", 1).await);
    assert!(!once_per_window(Some(&redis), "once", 1).await);

    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert!(under_limit(Some(&redis), "counted", 2, 1).await);
    assert!(once_per_window(Some(&redis), "once", 1).await);
}
