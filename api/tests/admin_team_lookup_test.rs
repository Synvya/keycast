#![cfg(feature = "integration-tests")]

// ABOUTME: Integration tests for TeamRepository::search_by_name, the helper
// ABOUTME: behind GET /api/admin/team-lookup. Covers case-insensitive substring
// ABOUTME: matching, tenant scoping, admin email aggregation, has_stored_key
// ABOUTME: flag, and the result limit.

use keycast_core::custom_permissions::allowed_kinds::AllowedKindsConfig;
use keycast_core::repositories::TeamRepository;
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

async fn ensure_tenant(pool: &PgPool, tenant_id: i64) {
    // The tenants table requires (id, domain, name) — domain is NOT NULL.
    sqlx::query(
        "INSERT INTO tenants (id, domain, name, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(format!("test-tenant-{}.example.test", tenant_id))
    .bind(format!("test-tenant-{}", tenant_id))
    .execute(pool)
    .await
    .expect("ensure_tenant insert must succeed");
}

/// Create or update a user with optional email. The unique index on `users`
/// is on `pubkey` alone (`users_pubkey_idx`), not `(pubkey, tenant_id)`.
async fn ensure_user_with_email(pool: &PgPool, tenant_id: i64, pubkey: &str, email: Option<&str>) {
    sqlx::query(
        "INSERT INTO users (pubkey, tenant_id, email, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())
         ON CONFLICT (pubkey) DO UPDATE
             SET email = EXCLUDED.email,
                 tenant_id = EXCLUDED.tenant_id",
    )
    .bind(pubkey)
    .bind(tenant_id)
    .bind(email)
    .execute(pool)
    .await
    .expect("ensure_user_with_email insert must succeed");
}

/// Create a team with the given admin and (optionally) a stored key.
/// Returns `(team_id, Option<stored_key_pubkey>)`.
async fn create_team(
    pool: &PgPool,
    tenant_id: i64,
    name: &str,
    admin_pubkey: &str,
    with_stored_key: bool,
) -> (i32, Option<String>) {
    ensure_tenant(pool, tenant_id).await;
    ensure_user_with_email(pool, tenant_id, admin_pubkey, None).await;

    let team_repo = TeamRepository::new(pool.clone());
    let allowed_kinds_config = serde_json::to_value(AllowedKindsConfig::default()).unwrap();
    let twr = team_repo
        .create_with_admin(tenant_id, name, admin_pubkey, allowed_kinds_config)
        .await
        .expect("create_with_admin should succeed");

    let stored_pubkey = if with_stored_key {
        let pubkey_hex = Keys::generate().public_key().to_hex();
        sqlx::query(
            "INSERT INTO stored_keys (tenant_id, team_id, name, pubkey, secret_key, created_at, updated_at)
             VALUES ($1, $2, 'test-key', $3, $4::bytea, NOW(), NOW())",
        )
        .bind(tenant_id)
        .bind(twr.team.id)
        .bind(&pubkey_hex)
        .bind(b"placeholder-encrypted-key".as_ref())
        .execute(pool)
        .await
        .expect("stored_key insert should succeed");
        Some(pubkey_hex)
    } else {
        None
    };

    (twr.team.id, stored_pubkey)
}

async fn cleanup_team(pool: &PgPool, tenant_id: i64, team_id: i32) {
    let _ = sqlx::query("DELETE FROM stored_keys WHERE team_id = $1 AND tenant_id = $2")
        .bind(team_id)
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "DELETE FROM policy_permissions WHERE policy_id IN (SELECT id FROM policies WHERE team_id = $1)",
    )
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
async fn test_search_matches_substring_case_insensitive() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let unique = Uuid::new_v4().to_string();
    // Two teams; target name carries an uppercase prefix so we can verify the
    // case-insensitive match. The disambiguating substring lives at the start.
    let target_name = format!("JoesDiner-{}", unique);
    let unrelated_name = format!("BellaBistro-{}", unique);

    let (target, _) = create_team(&pool, TENANT_A, &target_name, &admin, true).await;
    let (unrelated, _) = create_team(&pool, TENANT_A, &unrelated_name, &admin, true).await;

    let team_repo = TeamRepository::new(pool.clone());
    // Lowercase substring of the target name. Must match `JoesDiner-…`
    // case-insensitively and must NOT match `BellaBistro-…`.
    let results = team_repo
        .search_by_name(TENANT_A, &format!("joesdiner-{}", &unique[..8]), 25)
        .await
        .expect("search should succeed");

    let ids: Vec<i32> = results.iter().map(|r| r.id).collect();
    assert!(ids.contains(&target), "target team must be in results");
    assert!(
        !ids.contains(&unrelated),
        "unrelated team must NOT be in results"
    );

    cleanup_team(&pool, TENANT_A, target).await;
    cleanup_team(&pool, TENANT_A, unrelated).await;
}

#[tokio::test]
async fn test_search_aggregates_admin_emails() {
    let pool = setup_pool().await;
    let admin1 = Keys::generate().public_key().to_hex();
    let admin2 = Keys::generate().public_key().to_hex();
    let member = Keys::generate().public_key().to_hex();
    let unique = Uuid::new_v4().to_string();
    let team_name = format!("Multi Admin {}", unique);

    ensure_tenant(&pool, TENANT_A).await;
    ensure_user_with_email(&pool, TENANT_A, &admin1, Some("admin1@example.com")).await;
    ensure_user_with_email(&pool, TENANT_A, &admin2, Some("admin2@example.com")).await;
    ensure_user_with_email(&pool, TENANT_A, &member, Some("member@example.com")).await;

    let team_repo = TeamRepository::new(pool.clone());
    let allowed_kinds_config = serde_json::to_value(AllowedKindsConfig::default()).unwrap();
    let twr = team_repo
        .create_with_admin(TENANT_A, &team_name, &admin1, allowed_kinds_config)
        .await
        .expect("create");
    let team_id = twr.team.id;

    team_repo
        .add_member(team_id, &admin2, "admin")
        .await
        .expect("add second admin");
    team_repo
        .add_member(team_id, &member, "member")
        .await
        .expect("add member");

    let results = team_repo
        .search_by_name(TENANT_A, &unique, 25)
        .await
        .expect("search");
    let row = results.iter().find(|r| r.id == team_id).expect("hit");

    let mut emails = row.admin_emails.clone();
    emails.sort();
    assert_eq!(
        emails,
        vec![
            "admin1@example.com".to_string(),
            "admin2@example.com".to_string()
        ],
        "admin emails must include both admins, deduped, and exclude the member"
    );

    cleanup_team(&pool, TENANT_A, team_id).await;
}

#[tokio::test]
async fn test_search_has_stored_key_flag() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let unique = Uuid::new_v4().to_string();

    let (with_key, with_key_pubkey) = create_team(
        &pool,
        TENANT_A,
        &format!("WithKey {}", unique),
        &admin,
        true,
    )
    .await;
    let (without_key, _) =
        create_team(&pool, TENANT_A, &format!("NoKey {}", unique), &admin, false).await;

    let team_repo = TeamRepository::new(pool.clone());
    let results = team_repo
        .search_by_name(TENANT_A, &unique, 25)
        .await
        .expect("search");

    let with = results.iter().find(|r| r.id == with_key).expect("with");
    let without = results
        .iter()
        .find(|r| r.id == without_key)
        .expect("without");

    assert!(with.has_stored_key, "team with stored key must flag true");
    assert!(
        !without.has_stored_key,
        "team without stored key must flag false"
    );

    let rk_pubkeys: Vec<&str> = with
        .restaurant_keys
        .iter()
        .map(|rk| rk.pubkey.as_str())
        .collect();
    assert_eq!(
        rk_pubkeys,
        vec![with_key_pubkey.as_deref().unwrap()],
        "restaurant_keys must contain the stored key pubkey"
    );
    assert!(
        without.restaurant_keys.is_empty(),
        "team without stored key must have empty restaurant_keys"
    );

    cleanup_team(&pool, TENANT_A, with_key).await;
    cleanup_team(&pool, TENANT_A, without_key).await;
}

#[tokio::test]
async fn test_search_is_tenant_scoped() {
    let pool = setup_pool().await;
    const TENANT_B: i64 = 999_001;
    let admin_a = Keys::generate().public_key().to_hex();
    let admin_b = Keys::generate().public_key().to_hex();
    let unique = Uuid::new_v4().to_string();
    let shared_name = format!("Cross Tenant {}", unique);

    let (team_a, _) = create_team(&pool, TENANT_A, &shared_name, &admin_a, true).await;
    let (team_b, _) = create_team(&pool, TENANT_B, &shared_name, &admin_b, true).await;

    let team_repo = TeamRepository::new(pool.clone());

    let results_a = team_repo
        .search_by_name(TENANT_A, &unique, 25)
        .await
        .expect("search A");
    let ids_a: Vec<i32> = results_a.iter().map(|r| r.id).collect();
    assert!(ids_a.contains(&team_a));
    assert!(
        !ids_a.contains(&team_b),
        "tenant B's team must not leak to tenant A"
    );

    let results_b = team_repo
        .search_by_name(TENANT_B, &unique, 25)
        .await
        .expect("search B");
    let ids_b: Vec<i32> = results_b.iter().map(|r| r.id).collect();
    assert!(ids_b.contains(&team_b));
    assert!(
        !ids_b.contains(&team_a),
        "tenant A's team must not leak to tenant B"
    );

    cleanup_team(&pool, TENANT_A, team_a).await;
    cleanup_team(&pool, TENANT_B, team_b).await;
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(TENANT_B)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn test_search_respects_limit() {
    let pool = setup_pool().await;
    let admin = Keys::generate().public_key().to_hex();
    let unique = Uuid::new_v4().to_string();
    let mut team_ids = Vec::new();

    for i in 0..5 {
        let (id, _) = create_team(
            &pool,
            TENANT_A,
            &format!("LimitTest {} {}", unique, i),
            &admin,
            false,
        )
        .await;
        team_ids.push(id);
    }

    let team_repo = TeamRepository::new(pool.clone());
    let results = team_repo
        .search_by_name(TENANT_A, &unique, 3)
        .await
        .expect("search");

    assert_eq!(results.len(), 3, "limit must be respected");

    for id in team_ids {
        cleanup_team(&pool, TENANT_A, id).await;
    }
}
