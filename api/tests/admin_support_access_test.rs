#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for the AuthorizationRepository::find_active_support_for_caller
// ABOUTME: helper that backs DELETE /api/admin/teams/:id/support-access (label-prefix filter,
// ABOUTME: tenant scoping, team scoping, exclusion of revoked rows).

use keycast_core::custom_permissions::allowed_kinds::AllowedKindsConfig;
use keycast_core::repositories::{AuthorizationRepository, TeamRepository};
use nostr_sdk::Keys;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

const TENANT_A: i64 = 1;

async fn setup_pool() -> PgPool {
    common::assert_test_database_url();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/keycast_test".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Ensure a tenant row exists. The default tenant_id=1 is created by initial
/// migrations; second tenant is inserted lazily for the cross-tenant test.
async fn ensure_tenant(pool: &PgPool, tenant_id: i64) {
    let _ = sqlx::query(
        "INSERT INTO tenants (id, name, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(format!("test-tenant-{}", tenant_id))
    .execute(pool)
    .await;
}

/// Ensure a user row exists for a pubkey on a given tenant.
async fn ensure_user(pool: &PgPool, tenant_id: i64, pubkey: &str) {
    let _ = sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, created_at, updated_at)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (pubkey, tenant_id) DO NOTHING",
    )
    .bind(pubkey)
    .bind(tenant_id)
    .execute(pool)
    .await;
}

struct Fixture {
    team_id: i32,
    stored_key_id: i32,
    policy_id: i32,
}

/// Provision a team with a stored key and an "All Access" policy, returning ids.
/// Each test gets a fresh team with a unique name to avoid cross-test pollution.
async fn provision_team(pool: &PgPool, tenant_id: i64, admin_pubkey: &str) -> Fixture {
    ensure_tenant(pool, tenant_id).await;
    ensure_user(pool, tenant_id, admin_pubkey).await;

    let team_repo = TeamRepository::new(pool.clone());
    let allowed_kinds_config = serde_json::to_value(AllowedKindsConfig::default()).unwrap();
    let team_name = format!("Test Team {}", Uuid::new_v4());

    let team_with_relations = team_repo
        .create_with_admin(tenant_id, &team_name, admin_pubkey, allowed_kinds_config)
        .await
        .expect("create_with_admin should succeed");

    let team_id = team_with_relations.team.id;
    let policy_id = team_with_relations.policies[0].policy.id;

    // Insert a stored key directly. StoredKeyRepository::create requires a
    // fully-encrypted secret; for label-filter tests a placeholder secret_key
    // blob is sufficient.
    let pubkey_hex = Keys::generate().public_key().to_hex();
    let stored_key_id: i32 = sqlx::query_scalar(
        "INSERT INTO stored_keys (tenant_id, team_id, name, pubkey, secret_key, created_at, updated_at)
         VALUES ($1, $2, 'test-key', $3, $4::bytea, NOW(), NOW())
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(&pubkey_hex)
    .bind(b"placeholder-encrypted-key".as_ref())
    .fetch_one(pool)
    .await
    .expect("stored_key insert should succeed");

    Fixture {
        team_id,
        stored_key_id,
        policy_id,
    }
}

async fn insert_authorization(
    repo: &AuthorizationRepository,
    tenant_id: i64,
    fixture: &Fixture,
    label: Option<&str>,
) -> i32 {
    let bunker_pubkey = Keys::generate().public_key().to_hex();
    let relays = serde_json::json!(Vec::<String>::new());
    let auth = repo
        .create(
            tenant_id,
            fixture.stored_key_id,
            fixture.policy_id,
            "test-secret-hash",
            &bunker_pubkey,
            &relays,
            None,
            None,
            label,
        )
        .await
        .expect("auth insert should succeed");
    auth.id
}

async fn cleanup_team(pool: &PgPool, tenant_id: i64, team_id: i32) {
    // Cascade-friendly cleanup in dependency order.
    let _ = sqlx::query(
        "DELETE FROM authorizations WHERE stored_key_id IN
            (SELECT id FROM stored_keys WHERE team_id = $1 AND tenant_id = $2)",
    )
    .bind(team_id)
    .bind(tenant_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM stored_keys WHERE team_id = $1 AND tenant_id = $2")
        .bind(team_id)
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM policy_permissions WHERE policy_id IN (SELECT id FROM policies WHERE team_id = $1)")
        .bind(team_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM policies WHERE team_id = $1")
        .bind(team_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM team_users WHERE team_id = $1")
        .bind(team_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM teams WHERE id = $1 AND tenant_id = $2")
        .bind(team_id)
        .bind(tenant_id)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn test_find_active_support_returns_only_caller_label() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let support = Keys::generate().public_key().to_hex();
    let other_support = Keys::generate().public_key().to_hex();

    let fx = provision_team(&pool, TENANT_A, &admin).await;
    let repo = AuthorizationRepository::new(pool.clone());

    // Caller's own support-labeled auth — should match.
    let mine =
        insert_authorization(&repo, TENANT_A, &fx, Some(&format!("support:{}", support))).await;

    // A different support admin's auth on the same team — should NOT match.
    let other = insert_authorization(
        &repo,
        TENANT_A,
        &fx,
        Some(&format!("support:{}", other_support)),
    )
    .await;

    // An owner-minted auth with no support label — should NOT match.
    let owner_auth = insert_authorization(&repo, TENANT_A, &fx, Some("server-bunker")).await;

    // A null-label auth — should NOT match.
    let null_label_auth = insert_authorization(&repo, TENANT_A, &fx, None).await;

    let found = repo
        .find_active_support_for_caller(TENANT_A, fx.team_id, &support)
        .await
        .expect("query should succeed");

    let ids: Vec<i32> = found.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&mine), "caller's own auth must be returned");
    assert!(
        !ids.contains(&other),
        "another support admin's auth must NOT be returned"
    );
    assert!(
        !ids.contains(&owner_auth),
        "owner-minted auth must NOT be returned"
    );
    assert!(
        !ids.contains(&null_label_auth),
        "null-label auth must NOT be returned"
    );

    cleanup_team(&pool, TENANT_A, fx.team_id).await;
}

#[tokio::test]
async fn test_find_active_support_excludes_revoked() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let support = Keys::generate().public_key().to_hex();

    let fx = provision_team(&pool, TENANT_A, &admin).await;
    let repo = AuthorizationRepository::new(pool.clone());

    let label = format!("support:{}", support);
    let live = insert_authorization(&repo, TENANT_A, &fx, Some(&label)).await;
    let to_revoke = insert_authorization(&repo, TENANT_A, &fx, Some(&label)).await;

    repo.revoke(TENANT_A, to_revoke, Some("test"))
        .await
        .expect("revoke should succeed");

    let found = repo
        .find_active_support_for_caller(TENANT_A, fx.team_id, &support)
        .await
        .expect("query should succeed");

    let ids: Vec<i32> = found.iter().map(|(id, _)| *id).collect();
    assert!(ids.contains(&live), "live auth must be returned");
    assert!(
        !ids.contains(&to_revoke),
        "revoked auth must NOT be returned"
    );

    cleanup_team(&pool, TENANT_A, fx.team_id).await;
}

#[tokio::test]
async fn test_find_active_support_is_team_scoped() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let support = Keys::generate().public_key().to_hex();

    let fx_a = provision_team(&pool, TENANT_A, &admin).await;
    let fx_b = provision_team(&pool, TENANT_A, &admin).await;
    let repo = AuthorizationRepository::new(pool.clone());

    let label = format!("support:{}", support);
    let on_a = insert_authorization(&repo, TENANT_A, &fx_a, Some(&label)).await;
    let on_b = insert_authorization(&repo, TENANT_A, &fx_b, Some(&label)).await;

    let found_a = repo
        .find_active_support_for_caller(TENANT_A, fx_a.team_id, &support)
        .await
        .expect("query should succeed");
    let ids_a: Vec<i32> = found_a.iter().map(|(id, _)| *id).collect();
    assert!(ids_a.contains(&on_a));
    assert!(
        !ids_a.contains(&on_b),
        "team B auth must not appear for team A query"
    );

    cleanup_team(&pool, TENANT_A, fx_a.team_id).await;
    cleanup_team(&pool, TENANT_A, fx_b.team_id).await;
}

#[tokio::test]
async fn test_find_active_support_label_suffix_matches() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let support = Keys::generate().public_key().to_hex();

    let fx = provision_team(&pool, TENANT_A, &admin).await;
    let repo = AuthorizationRepository::new(pool.clone());

    // Grant endpoint stamps `support:{caller} (suffix)` when a label suffix is
    // supplied; the LIKE filter must match the prefix variant.
    let with_suffix = insert_authorization(
        &repo,
        TENANT_A,
        &fx,
        Some(&format!("support:{} (manual debug)", support)),
    )
    .await;

    let found = repo
        .find_active_support_for_caller(TENANT_A, fx.team_id, &support)
        .await
        .expect("query should succeed");

    let ids: Vec<i32> = found.iter().map(|(id, _)| *id).collect();
    assert!(
        ids.contains(&with_suffix),
        "labels with a suffix must still match the prefix filter"
    );

    cleanup_team(&pool, TENANT_A, fx.team_id).await;
}
