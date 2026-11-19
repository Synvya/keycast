#![cfg(feature = "integration-tests")]

// ABOUTME: Tests buyer teams on the customer tenant: the team key, roles, grants and sent_by
// ABOUTME: Also proves the generic team routes stay closed on the customer hostname

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use keycast_api::api::http::auth::generate_server_signed_ucan;
use keycast_api::api::http::confirmations::token_hash;
use keycast_api::api::http::routes::api_routes;
use keycast_api::api::tenant::Tenant;
use keycast_api::bcrypt_queue::BcryptQueue;
use keycast_api::handlers::http_rpc_handler::new_http_handler_cache;
use keycast_api::state::{get_tenant_cache, KeycastState, KEYCAST_STATE};
use keycast_core::encryption::{KeyManager, KeyManagerError};
use keycast_core::repositories::{
    MagicLinkTokenRepository, TeamInvitationRepository, PURPOSE_DELETE_ACCOUNT, PURPOSE_SIGN_IN,
};
use keycast_core::secret_pool::SecretPool;
use moka::future::Cache;
use nostr_sdk::{EventBuilder, Keys, Kind, PublicKey, Tag};
use serde_json::{json, Value};
use serial_test::serial;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use zeroize::Zeroizing;

const CUSTOMER_HOST: &str = "customers.buyers.example.com";
const OWNER_HOST: &str = "owners.buyers.example.com";

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
    request_with(app, method, host, path, bearer, &[], body).await
}

async fn request_with(
    app: &TestApp,
    method: Method,
    host: &str,
    path: &str,
    bearer: Option<&str>,
    extra: &[(&str, &str)],
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
    for (name, value) in extra {
        builder = builder.header(*name, *value);
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

async fn customer(app: &TestApp, method: Method, path: &str, session: &str, body: Value) -> Answer {
    request(app, method, CUSTOMER_HOST, path, Some(session), body).await
}

/// The link token of a confirmation. The table keeps only its hash, so the test sets a known one.
async fn link_token(app: &TestApp, confirmation_id: &str) -> String {
    let token = format!("test-token-{confirmation_id}");
    let updated = sqlx::query("UPDATE fresh_confirmations SET token_hash = $1 WHERE id = $2")
        .bind(token_hash(&token))
        .bind(confirmation_id)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        updated.rows_affected(),
        1,
        "no confirmation {confirmation_id}"
    );
    token
}

async fn confirm(app: &TestApp, token: &str, session: &str) -> Answer {
    customer(
        app,
        Method::POST,
        &format!("/api/customer/confirmations/{token}"),
        session,
        json!({}),
    )
    .await
}

async fn with_confirmation(
    app: &TestApp,
    path: &str,
    session: &str,
    confirmation_id: &str,
    body: Value,
) -> Answer {
    request_with(
        app,
        Method::POST,
        CUSTOMER_HOST,
        path,
        Some(session),
        &[("X-Synvya-Confirmation", confirmation_id)],
        body,
    )
    .await
}

/// A team change that needs a fresh confirmation: sent, answered 428, confirmed by the same
/// member through the link, and sent again with the confirmation. Any other first answer is
/// returned as it is.
async fn confirmed_change(app: &TestApp, path: &str, session: &str, body: Value) -> Answer {
    let first = customer(app, Method::POST, path, session, body.clone()).await;
    if first.status != StatusCode::PRECONDITION_REQUIRED {
        return first;
    }
    let id = first.body["confirmation_id"].as_str().unwrap().to_string();
    let token = link_token(app, &id).await;
    let confirmed = confirm(app, &token, session).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.raw);
    with_confirmation(app, path, session, &id, body).await
}

async fn admin_session(app: &TestApp) -> String {
    generate_server_signed_ucan(
        &Keys::generate().public_key(),
        app.owner_tenant,
        "admin@example.com",
        "https://admin.example.com",
        None,
        &app.server_keys,
        false,
        Some("full"),
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap()
}

async fn admin(app: &TestApp, method: Method, path: &str, body: Value) -> Answer {
    let session = admin_session(app).await;
    request(app, method, OWNER_HOST, path, Some(&session), body).await
}

/// A merchant's orders app on the approved list: its origin and its merchant's key.
struct Merchant {
    origin: String,
    pubkey: PublicKey,
}

async fn add_merchant(app: &TestApp) -> Merchant {
    let origin = format!("https://orders.shop-{}.example.com", Uuid::new_v4());
    let pubkey = Keys::generate().public_key();
    let answer = admin(
        app,
        Method::POST,
        "/api/admin/customer-origins",
        json!({ "origin": origin, "merchant_name": "Shop", "merchant_pubkey": pubkey.to_hex() }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    Merchant { origin, pubkey }
}

async fn new_link(app: &TestApp, email: &str, purpose: &str, page: &str) -> String {
    let token = Uuid::new_v4().to_string();
    MagicLinkTokenRepository::new(app.pool.clone())
        .create(
            app.customer_tenant,
            email,
            &token,
            purpose,
            page,
            Utc::now() + Duration::minutes(15),
            None,
        )
        .await
        .unwrap();
    token
}

/// A signed-in buyer at the merchant's app.
struct Buyer {
    email: String,
    pubkey: String,
    session: String,
}

async fn sign_in(app: &TestApp, merchant: &Merchant) -> Buyer {
    let email = format!("buyer-{}@example.com", Uuid::new_v4());
    let page = format!("{}/signin", merchant.origin);
    let token = new_link(app, &email, PURPOSE_SIGN_IN, &page).await;
    let answer = request(
        app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({ "token": token }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    let pubkey: String = sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    Buyer {
        email,
        pubkey,
        session: answer.body["session_token"].as_str().unwrap().to_string(),
    }
}

async fn create_team(app: &TestApp, buyer: &Buyer) -> String {
    let answer = customer(
        app,
        Method::POST,
        "/api/customer/teams",
        &buyer.session,
        json!({ "name": "Fernhollow Kitchen" }),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    assert_eq!(answer.body["role"], "admin");
    answer.body["team_pubkey"].as_str().unwrap().to_string()
}

/// Put a buyer on a team with a role, through the admin API and the role route.
async fn add_to_team(app: &TestApp, team: &str, by: &Buyer, buyer: &Buyer, role: &str) {
    let added = admin(
        app,
        Method::POST,
        &format!("/api/admin/customer-teams/{team}/admins"),
        json!({ "pubkey": buyer.pubkey }),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.raw);
    if role != "admin" {
        let changed = change_role(app, team, by, &buyer.pubkey, role).await;
        assert_eq!(changed.status, StatusCode::OK, "{}", changed.raw);
    }
}

async fn change_role(app: &TestApp, team: &str, by: &Buyer, member: &str, role: &str) -> Answer {
    confirmed_change(
        app,
        "/api/customer/teams/role",
        &by.session,
        json!({ "team_pubkey": team, "member_pubkey": member, "role": role }),
    )
    .await
}

async fn remove(app: &TestApp, team: &str, by: &Buyer, member: &str) -> Answer {
    confirmed_change(
        app,
        "/api/customer/teams/remove",
        &by.session,
        json!({ "team_pubkey": team, "member_pubkey": member }),
    )
    .await
}

async fn grant(app: &TestApp, team: &str, buyer: &Buyer, merchant: &Merchant) -> Answer {
    customer(
        app,
        Method::POST,
        "/api/customer/teams/grant",
        &buyer.session,
        json!({
            "team_pubkey": team,
            "client_id": merchant.origin,
            "redirect_uri": format!("{}/signin", merchant.origin),
            "scope": "policy:commerce_envelope",
            "merchant_pubkey": merchant.pubkey.to_hex(),
        }),
    )
    .await
}

/// A team grant at an origin, naming the merchant or leaving it out.
async fn grant_for(
    app: &TestApp,
    team: &str,
    buyer: &Buyer,
    origin: &str,
    merchant: Option<&PublicKey>,
) -> Answer {
    let mut body = json!({
        "team_pubkey": team,
        "client_id": origin,
        "redirect_uri": format!("{origin}/signin"),
        "scope": "policy:commerce_envelope",
    });
    if let Some(merchant) = merchant {
        body["merchant_pubkey"] = json!(merchant.to_hex());
    }
    customer(
        app,
        Method::POST,
        "/api/customer/teams/grant",
        &buyer.session,
        body,
    )
    .await
}

async fn rpc(app: &TestApp, session: &str, method: &str, params: Value) -> Answer {
    customer(
        app,
        Method::POST,
        "/api/nostr",
        session,
        json!({ "method": method, "params": params }),
    )
    .await
}

/// An unsigned commerce envelope from the team to the merchant, naming `sent_by` if given.
fn envelope(team: &str, merchant: &Merchant, sent_by: Option<&str>) -> String {
    let mut payload = json!({ "items": [] });
    if let Some(pubkey) = sent_by {
        payload["extensions"] = json!({ "openmarkets:sent_by": { "pubkey": pubkey } });
    }
    let event = EventBuilder::new(Kind::from(1327), payload.to_string())
        .tags([Tag::public_key(merchant.pubkey)])
        .build(PublicKey::from_hex(team).unwrap());
    serde_json::to_string(&event).unwrap()
}

async fn admin_count(app: &TestApp, team: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM team_users tu
         JOIN stored_keys sk ON sk.team_id = tu.team_id
         WHERE sk.pubkey = $1 AND tu.role = 'admin'",
    )
    .bind(team)
    .fetch_one(&app.pool)
    .await
    .unwrap()
}

#[tokio::test]
#[serial]
async fn test_generic_team_routes_stay_closed_on_the_customer_hostname() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let buyer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &buyer).await;

    for (method, path) in [
        (Method::GET, "/api/teams".to_string()),
        (Method::POST, "/api/teams".to_string()),
        (Method::GET, "/api/teams/1".to_string()),
        (Method::POST, "/api/teams/1/users".to_string()),
        (Method::POST, "/api/teams/1/invite".to_string()),
        (
            Method::POST,
            format!("/api/teams/1/keys/{team}/authorizations"),
        ),
        (Method::POST, "/api/invitations/accept".to_string()),
        (Method::GET, "/api/admin/customer-teams".to_string()),
        (Method::POST, "/api/customer/teams/unknown".to_string()),
    ] {
        let answer = customer(&app, method.clone(), &path, &buyer.session, json!({})).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method} {path}");
    }

    // The same generic route exists on another hostname: the guard, not routing, closed it
    let owner = request(
        &app,
        Method::GET,
        OWNER_HOST,
        "/api/teams",
        None,
        Value::Null,
    )
    .await;
    assert_ne!(owner.status, StatusCode::NOT_FOUND, "{}", owner.raw);
}

#[tokio::test]
#[serial]
async fn test_buyer_makes_a_team_with_its_own_key_and_lists_it() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let buyer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &buyer).await;

    assert_ne!(team, buyer.pubkey, "The team key is not the buyer's key");
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT sk.secret_key FROM stored_keys sk JOIN teams t ON t.id = sk.team_id
         WHERE sk.pubkey = $1 AND t.tenant_id = $2",
    )
    .bind(&team)
    .bind(app.customer_tenant)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        Keys::new(nostr_sdk::SecretKey::from_slice(&stored).unwrap())
            .public_key()
            .to_hex(),
        team,
        "Keycast holds the team's secret key"
    );

    let listed = customer(
        &app,
        Method::GET,
        "/api/customer/teams",
        &buyer.session,
        Value::Null,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.raw);
    let teams = listed.body["teams"].as_array().unwrap();
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0]["team_pubkey"], team.as_str());
    assert_eq!(teams[0]["name"], "Fernhollow Kitchen");
    assert_eq!(teams[0]["role"], "admin");
}

/// A team grant follows the origin's merchant list: a listed merchant is granted, an unlisted
/// one is refused, and an omitted one is allowed only while the list has one merchant.
#[tokio::test]
#[serial]
async fn test_team_grant_follows_the_origins_merchant_list() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;

    let omitted = grant_for(&app, &team, &owner, &merchant.origin, None).await;
    assert_eq!(omitted.status, StatusCode::OK, "{}", omitted.raw);

    let second = Keys::generate().public_key();
    let added = admin(
        &app,
        Method::POST,
        "/api/admin/customer-origins",
        json!({
            "origin": merchant.origin,
            "merchant_name": "Second Shop",
            "merchant_pubkey": second.to_hex(),
        }),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.raw);

    for listed in [&merchant.pubkey, &second] {
        let answer = grant_for(&app, &team, &owner, &merchant.origin, Some(listed)).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    }
    let unlisted = Keys::generate().public_key();
    let refused = grant_for(&app, &team, &owner, &merchant.origin, Some(&unlisted)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.raw);
    let omitted = grant_for(&app, &team, &owner, &merchant.origin, None).await;
    assert_eq!(omitted.status, StatusCode::BAD_REQUEST, "{}", omitted.raw);

    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE name LIKE $1")
        .bind(format!("commerce_envelope:{}:%", unlisted.to_hex()))
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(policies, 0, "An unlisted merchant gets no policy");
}

#[tokio::test]
#[serial]
async fn test_grants_follow_the_role() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let orderer = sign_in(&app, &merchant).await;
    let viewer = sign_in(&app, &merchant).await;
    let outsider = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &orderer, "orderer").await;
    add_to_team(&app, &team, &owner, &viewer, "viewer").await;

    for (buyer, permission) in [
        (&owner, "commerce_envelope"),
        (&orderer, "commerce_envelope"),
        (&viewer, "decrypt_only"),
    ] {
        let answer = grant(&app, &team, buyer, &merchant).await;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
        assert_eq!(answer.body["permission"], permission);
        assert!(answer.body["authorization"]["bunker_url"]
            .as_str()
            .unwrap()
            .starts_with("bunker://"));

        let session = answer.body["session_token"].as_str().unwrap();
        let pubkey = rpc(&app, session, "get_public_key", json!([])).await;
        assert_eq!(pubkey.status, StatusCode::OK, "{}", pubkey.raw);
        assert_eq!(pubkey.body["result"], team.as_str(), "Signs as the team");
    }

    let refused = grant(&app, &team, &outsider, &merchant).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.raw);
    let grants: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM authorizations WHERE member_pubkey = $1")
            .bind(&outsider.pubkey)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(grants, 0, "A person outside the team gets nothing");
}

#[tokio::test]
#[serial]
async fn test_viewer_reads_but_cannot_send() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let viewer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &viewer, "viewer").await;

    let answer = grant(&app, &team, &viewer, &merchant).await;
    let session = answer.body["session_token"].as_str().unwrap().to_string();

    let plaintext = envelope(&team, &merchant, Some(&viewer.pubkey));
    let sent = rpc(
        &app,
        &session,
        "nip44_encrypt",
        json!([merchant.pubkey.to_hex(), plaintext]),
    )
    .await;
    assert_eq!(sent.status, StatusCode::FORBIDDEN, "{}", sent.raw);

    // A reply the store sent to the team key
    let store = Keys::generate();
    let team_key = PublicKey::from_hex(&team).unwrap();
    let ciphertext = nostr_sdk::nips::nip44::encrypt(
        store.secret_key(),
        &team_key,
        "order accepted",
        nostr_sdk::nips::nip44::Version::V2,
    )
    .unwrap();
    let read = rpc(
        &app,
        &session,
        "nip44_decrypt",
        json!([store.public_key().to_hex(), ciphertext]),
    )
    .await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.raw);
    assert_eq!(read.body["result"], "order accepted");
}

#[tokio::test]
#[serial]
async fn test_team_key_encrypts_only_envelopes_sent_by_the_member_and_logs_them() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let orderer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &orderer, "orderer").await;

    let answer = grant(&app, &team, &orderer, &merchant).await;
    let session = answer.body["session_token"].as_str().unwrap().to_string();
    let recipient = merchant.pubkey.to_hex();

    let as_other = rpc(
        &app,
        &session,
        "nip44_encrypt",
        json!([recipient, envelope(&team, &merchant, Some(&owner.pubkey))]),
    )
    .await;
    assert_eq!(as_other.status, StatusCode::FORBIDDEN, "{}", as_other.raw);

    let unnamed = rpc(
        &app,
        &session,
        "nip44_encrypt",
        json!([recipient, envelope(&team, &merchant, None)]),
    )
    .await;
    assert_eq!(unnamed.status, StatusCode::FORBIDDEN, "{}", unnamed.raw);

    let as_member = rpc(
        &app,
        &session,
        "nip44_encrypt",
        json!([recipient, envelope(&team, &merchant, Some(&orderer.pubkey))]),
    )
    .await;
    assert_eq!(as_member.status, StatusCode::OK, "{}", as_member.raw);

    // The log names the grant and so the member. It is written in the background.
    let mut logged = 0i64;
    for _ in 0..50 {
        logged = sqlx::query_scalar(
            "SELECT COUNT(*) FROM team_signing_activity tsa
             JOIN authorizations a ON a.id = tsa.authorization_id
             WHERE tsa.member_pubkey = $1 AND a.member_pubkey = $1
               AND tsa.method = 'nip44_encrypt' AND tsa.event_kind = 1327",
        )
        .bind(&orderer.pubkey)
        .fetch_one(&app.pool)
        .await
        .unwrap();
        if logged > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        logged, 1,
        "One logged encryption, under the orderer's grant"
    );
}

#[tokio::test]
#[serial]
async fn test_magic_link_verify_takes_a_team_grant_for_members_only() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let outsider = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;

    let verify = |buyer: &Buyer| {
        let page = format!("{}/signin", merchant.origin);
        let email = buyer.email.clone();
        let app = &app;
        let merchant = &merchant;
        let team = team.clone();
        async move {
            let token = new_link(app, &email, PURPOSE_SIGN_IN, &page).await;
            request(
                app,
                Method::POST,
                CUSTOMER_HOST,
                "/api/auth/magic-link/verify",
                None,
                json!({
                    "token": token,
                    "client_id": merchant.origin,
                    "redirect_uri": page,
                    "scope": "policy:commerce_envelope",
                    "merchant_pubkey": merchant.pubkey.to_hex(),
                    "team_pubkey": team,
                }),
            )
            .await
        }
    };

    let member = verify(&owner).await;
    assert_eq!(member.status, StatusCode::OK, "{}", member.raw);
    let session = member.body["session_token"].as_str().unwrap();
    let pubkey = rpc(&app, session, "get_public_key", json!([])).await;
    assert_eq!(pubkey.body["result"], team.as_str());

    let refused = verify(&outsider).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.raw);
}

#[tokio::test]
#[serial]
async fn test_last_admin_cannot_leave_or_be_demoted() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let orderer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &orderer, "orderer").await;

    let demoted = change_role(&app, &team, &owner, &owner.pubkey, "orderer").await;
    assert_eq!(demoted.status, StatusCode::CONFLICT, "{}", demoted.raw);
    let left = remove(&app, &team, &owner, &owner.pubkey).await;
    assert_eq!(left.status, StatusCode::CONFLICT, "{}", left.raw);
    assert_eq!(admin_count(&app, &team).await, 1);

    // An orderer cannot change roles
    let by_orderer = change_role(&app, &team, &orderer, &orderer.pubkey, "admin").await;
    assert_eq!(
        by_orderer.status,
        StatusCode::FORBIDDEN,
        "{}",
        by_orderer.raw
    );

    // With a second admin, the first may leave
    let promoted = change_role(&app, &team, &owner, &orderer.pubkey, "admin").await;
    assert_eq!(promoted.status, StatusCode::OK, "{}", promoted.raw);
    let left = remove(&app, &team, &owner, &owner.pubkey).await;
    assert_eq!(left.status, StatusCode::OK, "{}", left.raw);
    assert_eq!(admin_count(&app, &team).await, 1);
}

#[tokio::test]
#[serial]
async fn test_removing_a_member_revokes_their_grants_on_the_team_key() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let orderer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &orderer, "orderer").await;

    let answer = grant(&app, &team, &orderer, &merchant).await;
    let session = answer.body["session_token"].as_str().unwrap().to_string();
    assert_eq!(
        rpc(&app, &session, "get_public_key", json!([]))
            .await
            .status,
        StatusCode::OK
    );

    let removed = remove(&app, &team, &owner, &orderer.pubkey).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.raw);
    assert_eq!(removed.body["revoked_grants"], 1);

    assert_eq!(
        rpc(&app, &session, "get_public_key", json!([]))
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "The grant stops on its next call"
    );
    let again = grant(&app, &team, &orderer, &merchant).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN, "{}", again.raw);
}

#[tokio::test]
#[serial]
async fn test_last_admin_can_still_delete_their_own_account() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let viewer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &viewer, "viewer").await;
    let owner_grant = grant(&app, &team, &owner, &merchant).await;
    let owner_grant = owner_grant.body["session_token"]
        .as_str()
        .unwrap()
        .to_string();

    let page = format!("{}/account", merchant.origin);
    let token = new_link(&app, &owner.email, PURPOSE_DELETE_ACCOUNT, &page).await;
    let verified = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({ "token": token }),
    )
    .await;
    let delete_session = verified.body["session_token"].as_str().unwrap();
    let deleted = customer(
        &app,
        Method::DELETE,
        "/api/customer/account",
        delete_session,
        Value::Null,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.raw);

    assert_eq!(
        admin_count(&app, &team).await,
        0,
        "The team is left with no admin"
    );
    assert_eq!(
        rpc(&app, &owner_grant, "get_public_key", json!([]))
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "The deleted member's grant on the team key ends"
    );

    // Support restores an admin through the admin API
    let restored = admin(
        &app,
        Method::POST,
        &format!("/api/admin/customer-teams/{team}/admins"),
        json!({ "email": viewer.email }),
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.raw);
    assert_eq!(admin_count(&app, &team).await, 1);

    let _ = sqlx::query("DELETE FROM customer_deletion_notices WHERE pubkey = $1")
        .bind(&owner.pubkey)
        .execute(&app.pool)
        .await;
}

#[tokio::test]
#[serial]
async fn test_admin_api_manages_teams_for_the_server() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let buyer = sign_in(&app, &merchant).await;

    // A team with no member, for a store invitation not yet accepted
    let created = admin(
        &app,
        Method::POST,
        "/api/admin/customer-teams",
        json!({ "name": "Invited Co" }),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.raw);
    let team = created.body["team_pubkey"].as_str().unwrap().to_string();

    let gone = admin(
        &app,
        Method::DELETE,
        &format!("/api/admin/customer-teams/{team}"),
        Value::Null,
    )
    .await;
    assert_eq!(gone.status, StatusCode::OK, "{}", gone.raw);

    // A team with a first admin
    let created = admin(
        &app,
        Method::POST,
        "/api/admin/customer-teams",
        json!({ "name": "Accepted Co", "admin_email": buyer.email }),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.raw);
    let team = created.body["team_pubkey"].as_str().unwrap().to_string();

    let members = admin(
        &app,
        Method::GET,
        &format!("/api/admin/customer-teams/{team}/members"),
        Value::Null,
    )
    .await;
    assert_eq!(members.status, StatusCode::OK, "{}", members.raw);
    let members = members.body["members"].as_array().unwrap().clone();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["pubkey"], buyer.pubkey.as_str());
    assert_eq!(members[0]["email"], buyer.email.as_str());
    assert_eq!(members[0]["role"], "admin");

    let teams = admin(
        &app,
        Method::GET,
        &format!("/api/admin/customer-teams?email={}", buyer.email),
        Value::Null,
    )
    .await;
    assert_eq!(teams.status, StatusCode::OK, "{}", teams.raw);
    assert_eq!(teams.body["teams"][0]["team_pubkey"], team.as_str());

    let refused = admin(
        &app,
        Method::DELETE,
        &format!("/api/admin/customer-teams/{team}"),
        Value::Null,
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.raw);

    // A closed account: the last admin goes only once no other member remains
    let other = sign_in(&app, &merchant).await;
    add_to_team(&app, &team, &buyer, &other, "orderer").await;
    let held = admin(
        &app,
        Method::DELETE,
        &format!("/api/admin/customer-teams/{team}/members/{}", buyer.pubkey),
        Value::Null,
    )
    .await;
    assert_eq!(held.status, StatusCode::CONFLICT, "{}", held.raw);
    assert!(held.raw.contains("last_admin"), "{}", held.raw);
    for member in [&other, &buyer] {
        let removed = admin(
            &app,
            Method::DELETE,
            &format!("/api/admin/customer-teams/{team}/members/{}", member.pubkey),
            Value::Null,
        )
        .await;
        assert_eq!(removed.status, StatusCode::OK, "{}", removed.raw);
        assert_eq!(removed.body["removed"], true);
    }
    let empty = admin(
        &app,
        Method::GET,
        &format!("/api/admin/customer-teams/{team}/members"),
        Value::Null,
    )
    .await;
    assert_eq!(
        empty.body["members"],
        json!([]),
        "The team stays, with its key"
    );
    let not_member = admin(
        &app,
        Method::DELETE,
        &format!("/api/admin/customer-teams/{team}/members/{}", buyer.pubkey),
        Value::Null,
    )
    .await;
    assert_eq!(
        not_member.status,
        StatusCode::NOT_FOUND,
        "{}",
        not_member.raw
    );

    // Not for anyone but a full admin
    let plain = request(
        &app,
        Method::GET,
        OWNER_HOST,
        &format!("/api/admin/customer-teams/{team}/members"),
        Some(&buyer.session),
        Value::Null,
    )
    .await;
    assert_ne!(plain.status, StatusCode::OK, "{}", plain.raw);
}

#[tokio::test]
#[serial]
async fn test_admin_invites_by_email_and_the_invitee_accepts() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    let invitee_email = format!("buyer-{}@example.com", Uuid::new_v4());

    let invited = confirmed_change(
        &app,
        "/api/customer/teams/invite",
        &owner.session,
        json!({
            "team_pubkey": team,
            "email": invitee_email,
            "role": "orderer",
            "app_url": format!("{}/team", merchant.origin),
        }),
    )
    .await;
    assert_eq!(invited.status, StatusCode::OK, "{}", invited.raw);
    assert_eq!(invited.body["invitation"]["role"], "orderer");

    let token: String = sqlx::query_scalar("SELECT token FROM team_invitations WHERE email = $1")
        .bind(&invitee_email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(TeamInvitationRepository::new(app.pool.clone())
        .find_valid_by_token(&token)
        .await
        .unwrap()
        .is_some());

    // Another person cannot use it
    let stranger = sign_in(&app, &merchant).await;
    let wrong = customer(
        &app,
        Method::POST,
        "/api/customer/teams/accept",
        &stranger.session,
        json!({ "token": token }),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{}", wrong.raw);

    // The invitee signs in with the invited email and accepts
    let page = format!("{}/signin", merchant.origin);
    let link = new_link(&app, &invitee_email, PURPOSE_SIGN_IN, &page).await;
    let verified = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({ "token": link }),
    )
    .await;
    let session = verified.body["session_token"].as_str().unwrap().to_string();
    let accepted = customer(
        &app,
        Method::POST,
        "/api/customer/teams/accept",
        &session,
        json!({ "token": token }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.raw);
    assert_eq!(accepted.body["team_pubkey"], team.as_str());
    assert_eq!(accepted.body["role"], "orderer");

    // An orderer cannot invite
    let by_orderer = customer(
        &app,
        Method::POST,
        "/api/customer/teams/invite",
        &session,
        json!({
            "team_pubkey": team,
            "email": format!("buyer-{}@example.com", Uuid::new_v4()),
            "role": "viewer",
            "app_url": format!("{}/team", merchant.origin),
        }),
    )
    .await;
    assert_eq!(
        by_orderer.status,
        StatusCode::FORBIDDEN,
        "{}",
        by_orderer.raw
    );
}

#[tokio::test]
#[serial]
async fn test_owner_tenant_teams_refuse_buyer_roles() {
    let app = setup().await;
    let owner = Keys::generate().public_key();
    let session = generate_server_signed_ucan(
        &owner,
        app.owner_tenant,
        "owner@example.com",
        "https://owners.example.com",
        None,
        &app.server_keys,
        true,
        None,
    )
    .await
    .map_err(|_| "failed to mint token")
    .unwrap();
    let created = request(
        &app,
        Method::POST,
        OWNER_HOST,
        "/api/teams",
        Some(&session),
        json!({ "name": "Restaurant" }),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.raw);
    let team_id = created.body["team"]["id"].as_i64().unwrap();

    let added = request(
        &app,
        Method::POST,
        OWNER_HOST,
        &format!("/api/teams/{team_id}/users"),
        Some(&session),
        // The owner routes spell roles as the enum does
        json!({ "user_pubkey": Keys::generate().public_key().to_hex(), "role": "Orderer" }),
    )
    .await;
    assert_eq!(added.status, StatusCode::BAD_REQUEST, "{}", added.raw);
}

/// The customer session route tells Synvya Server whose session a Bearer token is, and only for
/// a live token of the customer tenant.
#[tokio::test]
#[serial]
async fn test_customer_session_names_the_buyer_and_nothing_else() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let buyer = sign_in(&app, &merchant).await;

    let live = customer(
        &app,
        Method::GET,
        "/api/customer/session",
        &buyer.session,
        Value::Null,
    )
    .await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.raw);
    assert_eq!(live.body["pubkey"], buyer.pubkey.as_str());
    assert_eq!(live.body["email"], buyer.email.as_str());

    let forged = customer(
        &app,
        Method::GET,
        "/api/customer/session",
        "not-a-token",
        Value::Null,
    )
    .await;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED, "{}", forged.raw);

    let none = request(
        &app,
        Method::GET,
        CUSTOMER_HOST,
        "/api/customer/session",
        None,
        Value::Null,
    )
    .await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED, "{}", none.raw);

    // A token of the owner tenant is not a customer session.
    let owner_token = admin_session(&app).await;
    let other_tenant = customer(
        &app,
        Method::GET,
        "/api/customer/session",
        &owner_token,
        Value::Null,
    )
    .await;
    assert_eq!(
        other_tenant.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        other_tenant.raw
    );

    // The route exists only on the customer hostname.
    let on_owner_host = request(
        &app,
        Method::GET,
        OWNER_HOST,
        "/api/customer/session",
        Some(&buyer.session),
        Value::Null,
    )
    .await;
    assert_eq!(
        on_owner_host.status,
        StatusCode::NOT_FOUND,
        "{}",
        on_owner_host.raw
    );
}

// ============================================================================
// Fresh confirmation on member and role changes (store API contract §14.5)
// ============================================================================

fn invite_body(team: &str, merchant: &Merchant) -> Value {
    json!({
        "team_pubkey": team,
        "email": format!("buyer-{}@example.com", Uuid::new_v4()),
        "role": "viewer",
        "app_url": format!("{}/team", merchant.origin),
    })
}

async fn invitations_of(app: &TestApp, team_pubkey: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM team_invitations ti
         JOIN stored_keys sk ON sk.team_id = ti.team_id WHERE sk.pubkey = $1",
    )
    .bind(team_pubkey)
    .fetch_one(&app.pool)
    .await
    .unwrap()
}

#[tokio::test]
#[serial]
async fn test_a_team_change_answers_428_until_confirmed_and_changes_nothing_before() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    let path = "/api/customer/teams/invite";
    let body = invite_body(&team, &merchant);

    let first = customer(&app, Method::POST, path, &owner.session, body.clone()).await;
    assert_eq!(
        first.status,
        StatusCode::PRECONDITION_REQUIRED,
        "{}",
        first.raw
    );
    assert_eq!(first.body["code"], "confirmation_required");
    let id = first.body["confirmation_id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 32);
    assert!(first.body["expires_at"].as_str().is_some());
    assert_eq!(invitations_of(&app, &team).await, 0);

    // Sent again before the link is used: still 428, with a new confirmation.
    let early = with_confirmation(&app, path, &owner.session, &id, body.clone()).await;
    assert_eq!(
        early.status,
        StatusCode::PRECONDITION_REQUIRED,
        "{}",
        early.raw
    );
    assert_ne!(early.body["confirmation_id"], id.as_str());

    let token = link_token(&app, &id).await;
    let confirmed = confirm(&app, &token, &owner.session).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.raw);
    assert_eq!(confirmed.body["confirmation_id"], id.as_str());
    assert_eq!(confirmed.body["action"], "team_invite");
    assert!(confirmed.body["confirmed_at"].as_str().is_some());

    // Bound to the body: another invitation does not spend it.
    let other = with_confirmation(
        &app,
        path,
        &owner.session,
        &id,
        invite_body(&team, &merchant),
    )
    .await;
    assert_eq!(
        other.status,
        StatusCode::PRECONDITION_REQUIRED,
        "{}",
        other.raw
    );
    // Bound to the path: a remove with the same id is refused too.
    let elsewhere = with_confirmation(
        &app,
        "/api/customer/teams/remove",
        &owner.session,
        &id,
        json!({ "team_pubkey": team, "member_pubkey": owner.pubkey }),
    )
    .await;
    assert_eq!(
        elsewhere.status,
        StatusCode::PRECONDITION_REQUIRED,
        "{}",
        elsewhere.raw
    );

    let done = with_confirmation(&app, path, &owner.session, &id, body.clone()).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.raw);
    assert_eq!(invitations_of(&app, &team).await, 1);

    // Used once: the same confirmation does not run a second request.
    let again = with_confirmation(
        &app,
        path,
        &owner.session,
        &id,
        invite_body(&team, &merchant),
    )
    .await;
    assert_eq!(
        again.status,
        StatusCode::PRECONDITION_REQUIRED,
        "{}",
        again.raw
    );
}

#[tokio::test]
#[serial]
async fn test_only_the_member_who_asked_confirms_and_a_link_works_once() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let stranger = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    let first = customer(
        &app,
        Method::POST,
        "/api/customer/teams/invite",
        &owner.session,
        invite_body(&team, &merchant),
    )
    .await;
    let id = first.body["confirmation_id"].as_str().unwrap().to_string();
    let token = link_token(&app, &id).await;

    let by_stranger = confirm(&app, &token, &stranger.session).await;
    assert_eq!(
        by_stranger.status,
        StatusCode::NOT_FOUND,
        "{}",
        by_stranger.raw
    );
    assert_eq!(by_stranger.body["code"], "not_found");
    let no_session = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        &format!("/api/customer/confirmations/{token}"),
        None,
        json!({}),
    )
    .await;
    assert_eq!(
        no_session.status,
        StatusCode::NOT_FOUND,
        "{}",
        no_session.raw
    );
    let unknown = confirm(&app, "no-such-token", &owner.session).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{}", unknown.raw);

    assert_eq!(
        confirm(&app, &token, &owner.session).await.status,
        StatusCode::OK
    );
    let twice = confirm(&app, &token, &owner.session).await;
    assert_eq!(twice.status, StatusCode::GONE, "{}", twice.raw);
    assert_eq!(twice.body["code"], "confirmation_expired");

    // The route is not on the owner hostname.
    let on_owner_host = request(
        &app,
        Method::POST,
        OWNER_HOST,
        &format!("/api/customer/confirmations/{token}"),
        Some(&owner.session),
        json!({}),
    )
    .await;
    assert_eq!(
        on_owner_host.status,
        StatusCode::NOT_FOUND,
        "{}",
        on_owner_host.raw
    );
}

#[tokio::test]
#[serial]
async fn test_a_confirmation_expires_after_ten_minutes() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    let path = "/api/customer/teams/invite";
    let body = invite_body(&team, &merchant);
    let first = customer(&app, Method::POST, path, &owner.session, body.clone()).await;
    let id = first.body["confirmation_id"].as_str().unwrap().to_string();
    let expires_at =
        chrono::DateTime::parse_from_rfc3339(first.body["expires_at"].as_str().unwrap()).unwrap();
    let lifetime = expires_at.with_timezone(&Utc) - Utc::now();
    assert!(lifetime > Duration::minutes(9) && lifetime <= Duration::minutes(10));
    let token = link_token(&app, &id).await;

    // A link opened after it expired.
    sqlx::query(
        "UPDATE fresh_confirmations SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(&id)
    .execute(&app.pool)
    .await
    .unwrap();
    let late = confirm(&app, &token, &owner.session).await;
    assert_eq!(late.status, StatusCode::GONE, "{}", late.raw);

    // A confirmed link whose request comes back after it expired.
    sqlx::query(
        "UPDATE fresh_confirmations SET confirmed_at = NOW() - INTERVAL '5 seconds' WHERE id = $1",
    )
    .bind(&id)
    .execute(&app.pool)
    .await
    .unwrap();
    let after = with_confirmation(&app, path, &owner.session, &id, body).await;
    assert_eq!(
        after.status,
        StatusCode::PRECONDITION_REQUIRED,
        "{}",
        after.raw
    );
    assert_eq!(invitations_of(&app, &team).await, 0);
}

/// The team change log, read through the admin API from after `after`.
async fn team_events_after(app: &TestApp, after: i64) -> Vec<Value> {
    let answer = admin(
        app,
        Method::GET,
        &format!("/api/admin/customer-team-events?after={after}&limit=500"),
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    answer.body["events"].as_array().unwrap().clone()
}

/// How many entries of one team the change log answers from `since` on.
async fn team_events_since(app: &TestApp, team: &str, since: &str) -> usize {
    let answer = admin(
        app,
        Method::GET,
        &format!(
            "/api/admin/customer-team-events?since={}&limit=500",
            since.replace('+', "%2B")
        ),
        json!({}),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.raw);
    answer.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["team_pubkey"] == team)
        .count()
}

async fn last_team_event_id(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM customer_team_events")
        .fetch_one(&app.pool)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn test_each_member_change_is_logged_and_read_in_order() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let start = last_team_event_id(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    let invitee_email = format!("buyer-{}@example.com", Uuid::new_v4());

    let invited = confirmed_change(
        &app,
        "/api/customer/teams/invite",
        &owner.session,
        json!({
            "team_pubkey": team,
            "email": invitee_email,
            "role": "orderer",
            "app_url": format!("{}/team", merchant.origin),
        }),
    )
    .await;
    assert_eq!(invited.status, StatusCode::OK, "{}", invited.raw);
    let token: String = sqlx::query_scalar("SELECT token FROM team_invitations WHERE email = $1")
        .bind(&invitee_email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    let page = format!("{}/signin", merchant.origin);
    let link = new_link(&app, &invitee_email, PURPOSE_SIGN_IN, &page).await;
    let verified = request(
        &app,
        Method::POST,
        CUSTOMER_HOST,
        "/api/auth/magic-link/verify",
        None,
        json!({ "token": link }),
    )
    .await;
    let session = verified.body["session_token"].as_str().unwrap().to_string();
    let accepted = customer(
        &app,
        Method::POST,
        "/api/customer/teams/accept",
        &session,
        json!({ "token": token }),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.raw);
    let member: String =
        sqlx::query_scalar("SELECT pubkey FROM users WHERE email = $1 AND tenant_id = $2")
            .bind(&invitee_email)
            .bind(app.customer_tenant)
            .fetch_one(&app.pool)
            .await
            .unwrap();

    let changed = change_role(&app, &team, &owner, &member, "viewer").await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.raw);
    let left = confirmed_change(
        &app,
        "/api/customer/teams/remove",
        &session,
        json!({ "team_pubkey": team, "member_pubkey": member }),
    )
    .await;
    assert_eq!(left.status, StatusCode::OK, "{}", left.raw);

    let events: Vec<Value> = team_events_after(&app, start)
        .await
        .into_iter()
        .filter(|e| e["team_pubkey"] == team.as_str())
        .collect();
    let summary: Vec<(String, Value, Value, Value)> = events
        .iter()
        .map(|e| {
            (
                e["action"].as_str().unwrap().to_string(),
                e["member_pubkey"].clone(),
                e["role"].clone(),
                e["actor_pubkey"].clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                "joined".into(),
                json!(owner.pubkey),
                json!("admin"),
                json!(owner.pubkey)
            ),
            (
                "invited".into(),
                Value::Null,
                json!("orderer"),
                json!(owner.pubkey)
            ),
            (
                "joined".into(),
                json!(member),
                json!("orderer"),
                json!(member)
            ),
            (
                "role_set".into(),
                json!(member),
                json!("viewer"),
                json!(owner.pubkey)
            ),
            ("removed".into(), json!(member), Value::Null, json!(member)),
        ]
    );
    // The invitation and every change after it name the member by email
    for event in &events[1..] {
        assert_eq!(event["member_email"], invitee_email.as_str(), "{event}");
    }
    let ids: Vec<i64> = events.iter().map(|e| e["id"].as_i64().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "In id order: {ids:?}");

    // Read again from the last id: nothing newer, and next_after stays
    let last = *ids.last().unwrap();
    let answer = admin(
        &app,
        Method::GET,
        &format!("/api/admin/customer-team-events?after={last}"),
        json!({}),
    )
    .await;
    assert!(answer.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["team_pubkey"] != team.as_str()));
    assert!(answer.body["next_after"].as_i64().unwrap() >= last);
}

#[tokio::test]
#[serial]
async fn test_admin_api_changes_are_logged_with_no_actor() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let start = last_team_event_id(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let other = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &other, "admin").await;
    let removed = admin(
        &app,
        Method::DELETE,
        &format!("/api/admin/customer-teams/{team}/members/{}", other.pubkey),
        json!({}),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.raw);

    let events: Vec<Value> = team_events_after(&app, start)
        .await
        .into_iter()
        .filter(|e| {
            e["team_pubkey"] == team.as_str() && e["member_pubkey"] == other.pubkey.as_str()
        })
        .collect();
    let actions: Vec<&str> = events
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, vec!["joined", "removed"]);
    assert!(events.iter().all(|e| e["actor_pubkey"].is_null()));

    // `since` reads from a point in time: a time after the changes answers none of them, a time
    // before answers both; a bad time is refused.
    let later = (Utc::now() + Duration::minutes(5)).to_rfc3339();
    let earlier = (Utc::now() - Duration::minutes(5)).to_rfc3339();
    assert_eq!(team_events_since(&app, &team, &later).await, 0);
    assert_eq!(
        team_events_since(&app, &team, &earlier).await,
        3,
        "the owner's join, then the other's join and removal"
    );
    let bad = admin(
        &app,
        Method::GET,
        "/api/admin/customer-team-events?since=yesterday",
        json!({}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.raw);
}

#[tokio::test]
#[serial]
async fn test_signing_log_names_the_member_behind_a_signed_event() {
    let app = setup().await;
    let merchant = add_merchant(&app).await;
    let owner = sign_in(&app, &merchant).await;
    let orderer = sign_in(&app, &merchant).await;
    let team = create_team(&app, &owner).await;
    add_to_team(&app, &team, &owner, &orderer, "orderer").await;
    let answer = grant(&app, &team, &orderer, &merchant).await;
    let session = answer.body["session_token"].as_str().unwrap().to_string();

    let seal = serde_json::to_value(
        EventBuilder::new(Kind::from(13), "sealed").build(PublicKey::from_hex(&team).unwrap()),
    )
    .unwrap();
    let signed = rpc(&app, &session, "sign_event", json!([seal])).await;
    assert_eq!(signed.status, StatusCode::OK, "{}", signed.raw);
    let event_id = signed.body["result"]["id"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            serde_json::from_str::<Value>(signed.body["result"].as_str()?).ok()?["id"]
                .as_str()
                .map(str::to_string)
        })
        .expect("a signed event id");

    // Written in the background
    let mut row = None;
    for _ in 0..50 {
        let read = admin(
            &app,
            Method::GET,
            &format!("/api/admin/customer-signing-activity/{event_id}"),
            json!({}),
        )
        .await;
        if read.status == StatusCode::OK {
            row = Some(read.body);
            break;
        }
        assert_eq!(read.status, StatusCode::NOT_FOUND, "{}", read.raw);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let row = row.expect("the signature is in the log");
    assert_eq!(row["event_id"], event_id.as_str());
    assert_eq!(row["team_pubkey"], team.as_str());
    assert_eq!(row["member_pubkey"], orderer.pubkey.as_str());
    assert_eq!(row["member_email"], orderer.email.as_str());
    assert_eq!(row["method"], "sign_event");
    assert_eq!(row["event_kind"], 13);

    let unknown = admin(
        &app,
        Method::GET,
        &format!("/api/admin/customer-signing-activity/{}", "ab".repeat(32)),
        json!({}),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{}", unknown.raw);
    let bad = admin(
        &app,
        Method::GET,
        "/api/admin/customer-signing-activity/not-hex",
        json!({}),
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.raw);
}
