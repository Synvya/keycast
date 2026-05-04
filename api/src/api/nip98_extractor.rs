// ABOUTME: NIP-98 service-auth path for admin routes
// ABOUTME: Verifies Authorization: Nostr <base64> envelopes, resolves admin_role, anti-replay via Redis

use axum::http::request::Parts;
use axum::http::StatusCode;
use base64::prelude::*;
use nostr_sdk::{Event, JsonUtil};

use crate::api::extractors::{AuthError, UcanAuth};
use crate::api::http::admin::{is_full_admin, is_support_admin};
use crate::nip98;

/// TTL for anti-replay records in Redis. Slightly longer than the 60s
/// `created_at` tolerance window so the replay record outlives any envelope
/// that could still be considered fresh.
const REPLAY_TTL_SECONDS: u64 = 120;

/// Redis key prefix for replay protection records.
const REPLAY_KEY_PREFIX: &str = "nip98_replay";

/// Try to authenticate via the NIP-98 service-auth path.
///
/// Returns:
/// - `None` if the request does not carry an `Authorization: Nostr ...` header
///   (caller should fall through to the cookie path).
/// - `Some(Ok(UcanAuth))` if the envelope verifies and resolves to an
///   `admin_role` (which may itself be `None` if the pubkey is neither full
///   nor support admin).
/// - `Some(Err(AuthError))` if the header is present but verification fails.
///   The NIP-98 path is exclusive once the header is present — the caller
///   MUST NOT fall through to the cookie path on this error.
pub async fn try_authenticate_nip98(parts: &Parts) -> Option<Result<UcanAuth, AuthError>> {
    let auth_header_str = parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())?;

    if !auth_header_str.starts_with("Nostr ") {
        return None;
    }

    Some(authenticate_nip98(parts, auth_header_str).await)
}

async fn authenticate_nip98(parts: &Parts, auth_header: &str) -> Result<UcanAuth, AuthError> {
    let path = parts.uri.path().to_string();

    let Some(expected_url) = build_expected_url(parts) else {
        tracing::warn!(
            "NIP-98 service-auth: missing Host / X-Forwarded-Host (path: {})",
            path
        );
        return Err(unauthorized());
    };

    let method = parts.method.as_str();

    let validated =
        nip98::extract_and_validate(auth_header, &expected_url, method).map_err(|e| {
            tracing::warn!(
                "NIP-98 service-auth verification failed (path: {}): {}",
                path,
                e
            );
            unauthorized()
        })?;

    let pubkey_hex = validated.pubkey.to_hex();

    let event_id = parse_event_id(auth_header).map_err(|e| {
        // Should not happen — extract_and_validate already parsed the same bytes.
        tracing::warn!(
            "NIP-98 service-auth: failed to parse event id for replay check: {}",
            e
        );
        unauthorized()
    })?;

    check_replay(&event_id).await?;

    let probe = UcanAuth {
        pubkey: pubkey_hex.clone(),
        admin_role: None,
    };
    let admin_role = if is_full_admin(&probe) {
        Some("full".to_string())
    } else if is_support_admin(&probe).await {
        Some("support".to_string())
    } else {
        None
    };

    let pubkey_short = pubkey_hex.get(..8).unwrap_or(&pubkey_hex);
    tracing::debug!(
        "NIP-98 service-auth: authenticated pubkey={} admin_role={:?} path={}",
        pubkey_short,
        admin_role,
        path
    );

    Ok(UcanAuth {
        pubkey: pubkey_hex,
        admin_role,
    })
}

/// Reconstruct the URL the client signed. Trusts `X-Forwarded-Proto` and
/// `X-Forwarded-Host` set by the load balancer (Cloud Run / ALB) so that
/// HTTPS-signed envelopes verify even though the inbound request to the app
/// arrives as HTTP.
fn build_expected_url(parts: &Parts) -> Option<String> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| parts.uri.path().to_string());

    let host = parts
        .headers
        .get("x-forwarded-host")
        .or_else(|| parts.headers.get("host"))
        .and_then(|v| v.to_str().ok())?;

    let proto = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| {
            if host.contains(":443") || !host.contains(':') {
                "https"
            } else {
                "http"
            }
        });

    Some(format!("{}://{}{}", proto, host, path_and_query))
}

/// Parse the event id from a NIP-98 Authorization header.
fn parse_event_id(auth_header: &str) -> Result<String, String> {
    let base64_str = auth_header
        .strip_prefix("Nostr ")
        .ok_or_else(|| "missing Nostr prefix".to_string())?
        .trim();
    let json_bytes = BASE64_STANDARD
        .decode(base64_str)
        .map_err(|e| format!("base64: {}", e))?;
    let event = Event::from_json(&json_bytes).map_err(|e| format!("json: {}", e))?;
    Ok(event.id.to_hex())
}

/// Check Redis for envelope replay. Fail-closed on Redis errors — service
/// auth resolves to full-admin authority for `ALLOWED_PUBKEYS` callers, so
/// fail-open here would let a captured envelope be reused during an outage.
async fn check_replay(event_id: &str) -> Result<(), AuthError> {
    let state = crate::state::get_keycast_state().map_err(|e| {
        tracing::error!("NIP-98 anti-replay: keycast state unavailable: {:?}", e);
        service_unavailable()
    })?;

    let Some(redis) = state.redis.as_ref() else {
        tracing::error!(
            "NIP-98 anti-replay: Redis not configured — cannot enforce replay protection"
        );
        return Err(service_unavailable());
    };

    let key = format!("{}:{}", REPLAY_KEY_PREFIX, event_id);

    match redis.set_nx_ex(&key, "1", REPLAY_TTL_SECONDS).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!(
                "NIP-98 anti-replay: rejecting replayed envelope id={}",
                event_id
            );
            Err(unauthorized())
        }
        Err(e) => {
            tracing::error!("NIP-98 anti-replay: Redis SET NX failed: {}", e);
            Err(service_unavailable())
        }
    }
}

fn unauthorized() -> AuthError {
    AuthError::new(StatusCode::UNAUTHORIZED, "unauthorized".to_string())
}

fn service_unavailable() -> AuthError {
    AuthError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "service temporarily unavailable".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Method, Request, Uri};
    use nostr_sdk::{EventBuilder, Keys, Kind, Tag};

    fn parts_from(uri: &str, method: Method, headers: Vec<(&str, &str)>) -> Parts {
        let mut req = Request::builder()
            .method(method)
            .uri(uri.parse::<Uri>().unwrap())
            .body(())
            .unwrap();
        let hdrs: &mut HeaderMap = req.headers_mut();
        for (k, v) in headers {
            hdrs.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        req.into_parts().0
    }

    #[test]
    fn build_expected_url_uses_forwarded_proto_and_host() {
        let parts = parts_from(
            "/api/admin/support-admins?x=1",
            Method::POST,
            vec![
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "auth.synvya.com"),
                ("Host", "internal-host"),
            ],
        );
        let url = build_expected_url(&parts).unwrap();
        assert_eq!(url, "https://auth.synvya.com/api/admin/support-admins?x=1");
    }

    #[test]
    fn build_expected_url_falls_back_to_host_header() {
        let parts = parts_from(
            "/api/admin/support-admins",
            Method::POST,
            vec![("Host", "auth.synvya.com")],
        );
        let url = build_expected_url(&parts).unwrap();
        assert_eq!(url, "https://auth.synvya.com/api/admin/support-admins");
    }

    #[test]
    fn build_expected_url_returns_none_without_host() {
        let parts = parts_from("/api/admin/support-admins", Method::POST, vec![]);
        assert!(build_expected_url(&parts).is_none());
    }

    #[test]
    fn build_expected_url_preserves_query_string() {
        let parts = parts_from(
            "/api/admin/user-lookup?q=alice%40example.com",
            Method::GET,
            vec![("Host", "auth.synvya.com")],
        );
        let url = build_expected_url(&parts).unwrap();
        assert_eq!(
            url,
            "https://auth.synvya.com/api/admin/user-lookup?q=alice%40example.com"
        );
    }

    /// Build a NIP-98 Authorization header for the given keys/url/method.
    async fn make_header(keys: &Keys, url: &str, method: &str) -> String {
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", url]).unwrap(),
                Tag::parse(["method", method]).unwrap(),
            ])
            .sign(keys)
            .await
            .unwrap();
        format!("Nostr {}", BASE64_STANDARD.encode(event.as_json()))
    }

    #[tokio::test]
    async fn try_authenticate_returns_none_when_header_absent() {
        let parts = parts_from(
            "/api/admin/support-admins",
            Method::POST,
            vec![("Host", "auth.synvya.com")],
        );
        let result = try_authenticate_nip98(&parts).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn try_authenticate_returns_none_for_bearer_header() {
        let parts = parts_from(
            "/api/admin/support-admins",
            Method::POST,
            vec![
                ("Host", "auth.synvya.com"),
                ("Authorization", "Bearer some-token"),
            ],
        );
        let result = try_authenticate_nip98(&parts).await;
        assert!(result.is_none(), "Bearer header must fall through");
    }

    #[tokio::test]
    async fn parse_event_id_round_trips() {
        let keys = Keys::generate();
        let header = make_header(&keys, "https://auth.synvya.com/x", "POST").await;
        let id = parse_event_id(&header).expect("event id parse");
        assert_eq!(id.len(), 64, "event id is 32 bytes hex");
    }
}
