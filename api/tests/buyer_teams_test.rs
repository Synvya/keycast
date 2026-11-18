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

async fn customer(app: &TestApp, method: Method, path: &str, session: &str, body: Value) -> Answer {
    request(app, method, CUSTOMER_HOST, path, Some(session), body).await
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
    customer(
        app,
        Method::POST,
        "/api/customer/teams/role",
        &by.session,
        json!({ "team_pubkey": team, "member_pubkey": member, "role": role }),
    )
    .await
}

async fn remove(app: &TestApp, team: &str, by: &Buyer, member: &str) -> Answer {
    customer(
        app,
        Method::POST,
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

    let invited = customer(
        &app,
        Method::POST,
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
