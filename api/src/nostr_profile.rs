// ABOUTME: Fetch NIP-01 kind-0 metadata (name, picture) for a pubkey from configured relays.
// ABOUTME: Best-effort with a short timeout; callers fall back to local data on failure.

use nostr_sdk::prelude::*;
use serde::Deserialize;
use std::time::Duration;

/// Overall deadline for the relay round-trip. Kept short because this runs
/// inline in the invite-email HTTP handler.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Subset of kind-0 metadata we use in emails.
#[derive(Debug, Clone, Default)]
pub struct ProfileMetadata {
    /// Preferred human-readable name (`display_name` → `name`).
    pub display_name: Option<String>,
    /// Avatar URL (`picture`).
    pub picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Kind0Content {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

/// Fetch kind-0 metadata for `pubkey_hex` from the given relays.
///
/// Returns `None` on any failure (bad pubkey, no relays reachable, timeout,
/// no event, malformed JSON). Callers should fall back to local data.
pub async fn fetch_profile_metadata(
    pubkey_hex: &str,
    relays: &[String],
) -> Option<ProfileMetadata> {
    if relays.is_empty() {
        return None;
    }

    let public_key = match PublicKey::from_hex(pubkey_hex) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!("fetch_profile_metadata: invalid pubkey {}: {}", pubkey_hex, e);
            return None;
        }
    };

    let client = Client::default();
    for relay in relays {
        if let Err(e) = client.add_relay(relay.as_str()).await {
            tracing::debug!("fetch_profile_metadata: add_relay {} failed: {}", relay, e);
        }
    }
    client.connect().await;

    let filter = Filter::new()
        .author(public_key)
        .kind(Kind::Metadata)
        .limit(1);

    let result = match client.fetch_events(filter, FETCH_TIMEOUT).await {
        Ok(events) => events
            .into_iter()
            .next()
            .and_then(|ev| parse_kind0(&ev.content)),
        Err(e) => {
            tracing::warn!(
                "fetch_profile_metadata: fetch_events failed for {}: {}",
                pubkey_hex,
                e
            );
            None
        }
    };

    // Best-effort teardown so sockets don't linger.
    client.shutdown().await;

    result
}

fn parse_kind0(content: &str) -> Option<ProfileMetadata> {
    let parsed: Kind0Content = serde_json::from_str(content).ok()?;
    let display_name = parsed
        .display_name
        .and_then(non_empty)
        .or_else(|| parsed.name.and_then(non_empty));
    let picture = parsed.picture.and_then(non_empty);
    if display_name.is_none() && picture.is_none() {
        return None;
    }
    Some(ProfileMetadata {
        display_name,
        picture,
    })
}

fn non_empty(s: String) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_display_name_preferred_over_name() {
        let m = parse_kind0(r#"{"name":"short","display_name":"Long Name"}"#).unwrap();
        assert_eq!(m.display_name.as_deref(), Some("Long Name"));
        assert_eq!(m.picture, None);
    }

    #[test]
    fn falls_back_to_name_when_display_name_missing() {
        let m = parse_kind0(r#"{"name":"only"}"#).unwrap();
        assert_eq!(m.display_name.as_deref(), Some("only"));
    }

    #[test]
    fn ignores_empty_strings() {
        let m = parse_kind0(r#"{"name":"","display_name":"  ","picture":""}"#);
        assert!(m.is_none());
    }

    #[test]
    fn extracts_picture() {
        let m = parse_kind0(r#"{"name":"a","picture":"https://example.com/x.png"}"#).unwrap();
        assert_eq!(m.picture.as_deref(), Some("https://example.com/x.png"));
    }

    #[test]
    fn returns_none_on_bad_json() {
        assert!(parse_kind0("not json").is_none());
    }
}
