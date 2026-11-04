// ABOUTME: Tells Synvya Server when a customer account is deleted, so it can cancel their
// ABOUTME: subscriptions and remove their saved card. Signed with NIP-98, retried until acknowledged

use base64::{engine::general_purpose::STANDARD, Engine as _};
use keycast_core::repositories::{DeletionNotice, DeletionNoticeRepository, RepositoryError};
use nostr_sdk::{EventBuilder, Keys, Kind, Tag};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;

/// How often to look for notices to deliver.
const DELIVERY_INTERVAL_SECONDS: u64 = 60;
/// How many notices to send in one pass.
const DELIVERY_BATCH_SIZE: i64 = 50;
const REQUEST_TIMEOUT_SECONDS: u64 = 10;

/// The Authorization header for a NIP-98 request signed with Keycast's server key.
fn nip98_header(server_keys: &Keys, url: &str, body: &[u8]) -> Result<String, String> {
    let tag = |name: &str, value: String| {
        Tag::parse(vec![name.to_string(), value]).map_err(|e| e.to_string())
    };
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(vec![
            tag("u", url.to_string())?,
            tag("method", "POST".to_string())?,
            tag("payload", hex::encode(Sha256::digest(body)))?,
        ])
        .sign_with_keys(server_keys)
        .map_err(|e| e.to_string())?;
    let event_json = serde_json::to_string(&event).map_err(|e| e.to_string())?;

    Ok(format!("Nostr {}", STANDARD.encode(event_json)))
}

async fn send_notice(
    client: &reqwest::Client,
    server_keys: &Keys,
    url: &str,
    notice: &DeletionNotice,
) -> Result<(), String> {
    let body = serde_json::to_vec(&serde_json::json!({
        "pubkey": notice.pubkey,
        "deleted_at": notice.deleted_at.to_rfc3339(),
    }))
    .map_err(|e| e.to_string())?;

    let response = client
        .post(url)
        .header(
            reqwest::header::AUTHORIZATION,
            nip98_header(server_keys, url, &body)?,
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Server answered {}", response.status()))
    }
}

/// Send every notice that is due. Returns how many were acknowledged.
pub async fn deliver_due_notices(
    pool: &PgPool,
    client: &reqwest::Client,
    server_keys: &Keys,
    url: &str,
) -> Result<usize, RepositoryError> {
    let repo = DeletionNoticeRepository::new(pool.clone());
    let mut acknowledged = 0;

    for notice in repo.find_due(DELIVERY_BATCH_SIZE).await? {
        match send_notice(client, server_keys, url, &notice).await {
            Ok(()) => {
                repo.acknowledge(notice.id).await?;
                acknowledged += 1;
            }
            Err(e) => {
                tracing::warn!(
                    "Customer deletion notice {} not delivered (attempt {}): {}",
                    notice.id,
                    notice.attempts + 1,
                    e
                );
                repo.schedule_retry(&notice).await?;
            }
        }
    }

    Ok(acknowledged)
}

/// Deliver notices in the background. Until SYNVYA_SERVER_DELETION_URL is set they wait in the
/// table.
pub fn spawn_delivery_task(pool: PgPool, server_keys: Keys) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                tracing::error!("Failed to create client for deletion notices: {}", e);
                return;
            }
        };
        let mut interval = tokio::time::interval(Duration::from_secs(DELIVERY_INTERVAL_SECONDS));

        loop {
            interval.tick().await;

            let Some(url) = std::env::var("SYNVYA_SERVER_DELETION_URL")
                .ok()
                .filter(|url| !url.trim().is_empty())
            else {
                continue;
            };

            if let Err(e) = deliver_due_notices(&pool, &client, &server_keys, &url).await {
                tracing::error!("Failed to deliver customer deletion notices: {}", e);
            }
        }
    })
}
