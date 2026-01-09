// ABOUTME: NIP-98 HTTP Auth validation for admin login
// ABOUTME: Validates kind 27235 events for session-based admin authentication

use base64::prelude::*;
use chrono::Utc;
use nostr_sdk::{Event, JsonUtil, Kind, PublicKey};
use std::fmt;

/// Maximum age in seconds for NIP-98 events (per spec recommendation)
const MAX_EVENT_AGE_SECONDS: i64 = 60;

/// Result of successful NIP-98 validation
pub struct Nip98Auth {
    pub pubkey: PublicKey,
}

/// Errors that can occur during NIP-98 validation
#[derive(Debug)]
pub enum Nip98Error {
    /// Authorization header missing "Nostr " prefix
    InvalidHeaderFormat,
    /// Base64 decoding failed
    Base64DecodeError(String),
    /// JSON parsing failed
    JsonParseError(String),
    /// Event kind is not 27235 (HttpAuth)
    InvalidKind(u16),
    /// Schnorr signature verification failed
    InvalidSignature,
    /// Event created_at is too old (>60 seconds)
    EventExpired,
    /// URL tag doesn't match expected URL
    UrlMismatch { expected: String, actual: String },
    /// Method tag doesn't match expected method
    MethodMismatch { expected: String, actual: String },
    /// Required tag missing
    MissingTag(String),
}

impl fmt::Display for Nip98Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderFormat => {
                write!(f, "Authorization header must start with 'Nostr '")
            }
            Self::Base64DecodeError(e) => write!(f, "Base64 decode error: {}", e),
            Self::JsonParseError(e) => write!(f, "JSON parse error: {}", e),
            Self::InvalidKind(k) => write!(f, "Invalid event kind: {} (expected 27235)", k),
            Self::InvalidSignature => write!(f, "Invalid Schnorr signature"),
            Self::EventExpired => write!(
                f,
                "Event expired (created_at must be within {} seconds)",
                MAX_EVENT_AGE_SECONDS
            ),
            Self::UrlMismatch { expected, actual } => {
                write!(f, "URL mismatch: expected '{}', got '{}'", expected, actual)
            }
            Self::MethodMismatch { expected, actual } => {
                write!(
                    f,
                    "Method mismatch: expected '{}', got '{}'",
                    expected, actual
                )
            }
            Self::MissingTag(tag) => write!(f, "Missing required tag: '{}'", tag),
        }
    }
}

impl std::error::Error for Nip98Error {}

/// Extract and validate a NIP-98 auth event from an Authorization header.
///
/// # Arguments
/// * `auth_header` - The full Authorization header value (e.g., "Nostr base64...")
/// * `expected_url` - The exact URL this request is for
/// * `expected_method` - The HTTP method (GET, POST, etc.)
///
/// # Returns
/// * `Ok(Nip98Auth)` with the verified pubkey if validation succeeds
/// * `Err(Nip98Error)` describing what failed
pub fn extract_and_validate(
    auth_header: &str,
    expected_url: &str,
    expected_method: &str,
) -> Result<Nip98Auth, Nip98Error> {
    // 1. Strip "Nostr " prefix and decode base64
    let base64_str = auth_header
        .strip_prefix("Nostr ")
        .ok_or(Nip98Error::InvalidHeaderFormat)?
        .trim();

    let json_bytes = BASE64_STANDARD
        .decode(base64_str)
        .map_err(|e| Nip98Error::Base64DecodeError(e.to_string()))?;

    let json_str =
        String::from_utf8(json_bytes).map_err(|e| Nip98Error::JsonParseError(e.to_string()))?;

    // 2. Parse JSON to Event
    let event =
        Event::from_json(&json_str).map_err(|e| Nip98Error::JsonParseError(e.to_string()))?;

    // 3. Verify kind == 27235 (HttpAuth)
    if event.kind != Kind::HttpAuth {
        return Err(Nip98Error::InvalidKind(event.kind.as_u16()));
    }

    // 4. Verify Schnorr signature
    event.verify().map_err(|_| Nip98Error::InvalidSignature)?;

    // 5. Check created_at within 60 seconds
    let now = Utc::now().timestamp();
    let event_time = event.created_at.as_secs() as i64;
    if (now - event_time).abs() > MAX_EVENT_AGE_SECONDS {
        return Err(Nip98Error::EventExpired);
    }

    // 6. Extract and validate URL tag
    let url_tag = event
        .tags
        .iter()
        .find(|t| t.as_slice().first().map(|s| s.as_str()) == Some("u"))
        .ok_or_else(|| Nip98Error::MissingTag("u".to_string()))?;

    let actual_url = url_tag.as_slice().get(1).map(|s| s.as_str()).unwrap_or("");

    if actual_url != expected_url {
        return Err(Nip98Error::UrlMismatch {
            expected: expected_url.to_string(),
            actual: actual_url.to_string(),
        });
    }

    // 7. Extract and validate method tag
    let method_tag = event
        .tags
        .iter()
        .find(|t| t.as_slice().first().map(|s| s.as_str()) == Some("method"))
        .ok_or_else(|| Nip98Error::MissingTag("method".to_string()))?;

    let actual_method = method_tag
        .as_slice()
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("");

    if !actual_method.eq_ignore_ascii_case(expected_method) {
        return Err(Nip98Error::MethodMismatch {
            expected: expected_method.to_string(),
            actual: actual_method.to_string(),
        });
    }

    Ok(Nip98Auth {
        pubkey: event.pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, Keys, Tag};

    fn create_test_auth_header(keys: &Keys, url: &str, method: &str) -> String {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let event = EventBuilder::new(Kind::HttpAuth, "")
                .tags([
                    Tag::parse(["u", url]).unwrap(),
                    Tag::parse(["method", method]).unwrap(),
                ])
                .sign(keys)
                .await
                .unwrap();

            let json = event.as_json();
            format!("Nostr {}", BASE64_STANDARD.encode(json))
        })
    }

    #[test]
    fn test_valid_nip98_auth() {
        let keys = Keys::generate();
        let url = "https://example.com/api/auth/login";
        let method = "POST";

        let header = create_test_auth_header(&keys, url, method);
        let result = extract_and_validate(&header, url, method);

        assert!(result.is_ok());
        let auth = result.unwrap();
        assert_eq!(auth.pubkey, keys.public_key());
    }

    #[test]
    fn test_invalid_header_format() {
        let result = extract_and_validate("Bearer token123", "https://example.com", "POST");
        assert!(matches!(result, Err(Nip98Error::InvalidHeaderFormat)));
    }

    #[test]
    fn test_url_mismatch() {
        let keys = Keys::generate();
        let header = create_test_auth_header(&keys, "https://example.com/api/foo", "POST");

        let result = extract_and_validate(&header, "https://example.com/api/bar", "POST");
        assert!(matches!(result, Err(Nip98Error::UrlMismatch { .. })));
    }

    #[test]
    fn test_method_mismatch() {
        let keys = Keys::generate();
        let header = create_test_auth_header(&keys, "https://example.com/api/login", "GET");

        let result = extract_and_validate(&header, "https://example.com/api/login", "POST");
        assert!(matches!(result, Err(Nip98Error::MethodMismatch { .. })));
    }
}
