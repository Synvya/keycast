//! Synvya: the staff challenge, signed with the person's own key.
//!
//! `POST /api/user/staff-challenge/sign` signs one event of one shape for a
//! signed-in person: kind 27235 with exactly the tags `challenge_id`, `nonce`,
//! `person_pubkey` (the person's own key) and `expires_at`. Keycast builds the
//! event itself from the three values in the body, so a caller cannot add a
//! tag. Synvya Server's staff sign-in (`POST /api/staff/auth/verify`) accepts
//! that event and no other service does: the server's admin and merchant
//! sign-ins need an `admin_pubkey` or `merchant_pubkey` tag, and NIP-98 needs
//! `u` and `method`.
//!
//! The route needs no OAuth or bunker authorization for the origin, unlike
//! `/api/user/sign`. Instead the session's origin (the UCAN's
//! `redirect_origin`) must be in `STAFF_CHALLENGE_ORIGINS`. Unset, the route
//! signs nothing.
//!
//! Design: docs/synvya/staff-challenge.md. This file is Synvya-only and stays
//! out of upstream code, so an upstream merge does not touch it.

use axum::{extract::State, http::HeaderMap, Json};
use nostr_sdk::{EventBuilder, Keys, Kind, Tag, TagKind, Timestamp};
use serde::Deserialize;

use super::auth::{extract_user_and_origin_from_token, AuthError, SignEventResponse};
use super::routes::AuthState;
use keycast_core::repositories::PersonalKeysRepository;

/// The kind of the staff challenge: the kind 27235 auth event.
pub const STAFF_CHALLENGE_KIND: u16 = 27235;
const MAX_VALUE_LEN: usize = 128;

/// The origins whose sessions may have the staff challenge signed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StaffChallengeOrigins(Vec<String>);

impl StaffChallengeOrigins {
    /// The list from `STAFF_CHALLENGE_ORIGINS`, given `NODE_ENV` and
    /// `ALLOW_LOCALHOST_ORIGINS`. Each entry is a bare origin: a scheme, a host
    /// and an optional port, with no path.
    ///
    /// On a deployment (`NODE_ENV` `production` or `staging`) every entry must be
    /// `https`, unless `ALLOW_LOCALHOST_ORIGINS=true`. That flag is staging-only
    /// (it already lets local apps through CORS), so a local app pointed at
    /// staging can get the staff session, and production never accepts an `http`
    /// entry. Off a deployment, `http` is accepted. An `http` entry must name a
    /// local host: `localhost` or a name under `local.synvya.com`.
    pub fn from_values(
        value: Option<&str>,
        node_env: &str,
        allow_localhost: bool,
    ) -> Result<Self, String> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let deployment = node_env == "production" || node_env == "staging";
        let http_allowed = !deployment || allow_localhost;
        let mut origins = Vec::new();
        for raw in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let url = nostr_sdk::Url::parse(raw).map_err(|_| {
                format!("STAFF_CHALLENGE_ORIGINS has an entry that is not a URL: \"{raw}\"")
            })?;
            let bare = url.host_str().is_some()
                && (url.path() == "/" || url.path().is_empty())
                && url.query().is_none()
                && url.fragment().is_none()
                && !raw.ends_with('/')
                && !raw.contains('*');
            if !bare {
                return Err(format!(
                    "STAFF_CHALLENGE_ORIGINS entries are bare origins such as https://account.synvya.com, got \"{raw}\""
                ));
            }
            match url.scheme() {
                "https" => {}
                "http" if http_allowed => {
                    let host = url.host_str().unwrap_or_default();
                    if host != "localhost" && !host.ends_with(".local.synvya.com") {
                        return Err(format!(
                            "STAFF_CHALLENGE_ORIGINS http entries must name localhost or a host under local.synvya.com, got \"{raw}\""
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "STAFF_CHALLENGE_ORIGINS entries must be https when NODE_ENV={node_env} and ALLOW_LOCALHOST_ORIGINS is not true, got \"{raw}\""
                    ));
                }
            }
            origins.push(raw.to_string());
        }
        Ok(Self(origins))
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_values(
            std::env::var("STAFF_CHALLENGE_ORIGINS").ok().as_deref(),
            &std::env::var("NODE_ENV").unwrap_or_default(),
            std::env::var("ALLOW_LOCALHOST_ORIGINS").is_ok_and(|v| v == "true"),
        )
    }

    /// The list this process runs with, read once. Startup has already refused
    /// a bad value (`from_env` in main), so a failure here allows no origin.
    pub fn current() -> &'static Self {
        static ORIGINS: std::sync::OnceLock<StaffChallengeOrigins> = std::sync::OnceLock::new();
        ORIGINS.get_or_init(|| Self::from_env().unwrap_or_default())
    }

    pub fn allows(&self, origin: &str) -> bool {
        self.0.iter().any(|o| o == origin)
    }
}

#[derive(Debug, Deserialize)]
pub struct StaffChallengeRequest {
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at: String,
}

fn check_value(name: &str, value: &str) -> Result<(), AuthError> {
    let ok = !value.is_empty()
        && value.len() <= MAX_VALUE_LEN
        && value.chars().all(|c| c.is_ascii_graphic());
    if ok {
        Ok(())
    } else {
        Err(AuthError::BadRequest(format!(
            "{name} must be 1 to {MAX_VALUE_LEN} printable characters"
        )))
    }
}

/// The tags of the staff challenge, in the order Synvya Server reads them.
pub fn staff_challenge_tags(req: &StaffChallengeRequest, person_pubkey: &str) -> Vec<Tag> {
    [
        ("challenge_id", req.challenge_id.as_str()),
        ("nonce", req.nonce.as_str()),
        ("person_pubkey", person_pubkey),
        ("expires_at", req.expires_at.as_str()),
    ]
    .into_iter()
    .map(|(k, v)| Tag::custom(TagKind::custom(k), vec![v.to_string()]))
    .collect()
}

/// `POST /api/user/staff-challenge/sign`
pub async fn sign_staff_challenge(
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<StaffChallengeRequest>,
) -> Result<Json<SignEventResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let (user_pubkey, redirect_origin, _) =
        extract_user_and_origin_from_token(&headers, tenant_id).await?;

    if !StaffChallengeOrigins::current().allows(&redirect_origin) {
        tracing::warn!(
            event = "staff_challenge_refused",
            tenant_id,
            redirect_origin = %redirect_origin,
            "Staff challenge refused: origin not in STAFF_CHALLENGE_ORIGINS"
        );
        return Err(AuthError::Forbidden(
            "This app may not sign the staff challenge".to_string(),
        ));
    }
    check_value("challenge_id", &req.challenge_id)?;
    check_value("nonce", &req.nonce)?;
    check_value("expires_at", &req.expires_at)?;

    let pool = &auth_state.state.db;
    let encrypted = PersonalKeysRepository::new(pool.clone())
        .find_encrypted_key_for_tenant(&user_pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let secret = auth_state
        .state
        .key_manager
        .as_ref()
        .decrypt(&encrypted)
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;
    let secret_key = nostr_sdk::secp256k1::SecretKey::from_slice(&secret)
        .map_err(|e| AuthError::Internal(format!("Invalid secret key bytes: {}", e)))?;
    let keys = Keys::new(secret_key.into());

    let event = EventBuilder::new(Kind::from(STAFF_CHALLENGE_KIND), "")
        .tags(staff_challenge_tags(&req, &user_pubkey))
        .custom_created_at(Timestamp::now())
        .sign(&keys)
        .await
        .map_err(|e| AuthError::Internal(format!("Signing failed: {}", e)))?;

    tracing::info!(
        event = "staff_challenge_signed",
        tenant_id,
        redirect_origin = %redirect_origin,
        user_pubkey = %user_pubkey,
        "Signed the staff challenge"
    );
    let signed_event = serde_json::to_value(&event)
        .map_err(|e| AuthError::Internal(format!("JSON serialization failed: {}", e)))?;
    Ok(Json(SignEventResponse { signed_event }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_allows_no_origin() {
        let o = StaffChallengeOrigins::from_values(None, "production", false).unwrap();
        assert!(!o.allows("https://account.synvya.com"));
    }

    #[test]
    fn exact_origins_only() {
        let o = StaffChallengeOrigins::from_values(
            Some("https://account.synvya.com, https://account.staging.synvya.com"),
            "production",
            false,
        )
        .unwrap();
        assert!(o.allows("https://account.synvya.com"));
        assert!(o.allows("https://account.staging.synvya.com"));
        assert!(!o.allows("https://admin.synvya.com"));
        assert!(!o.allows("https://account.synvya.com.evil.example"));
    }

    #[test]
    fn http_off_a_deployment_or_with_allow_localhost_only() {
        let local = "http://account.local.synvya.com:5273";
        let from = |env, allow| StaffChallengeOrigins::from_values(Some(local), env, allow);
        assert!(from("development", false).is_ok());
        assert!(from("staging", false).is_err());
        assert!(from("production", false).is_err());
        // Staging runs NODE_ENV=production with ALLOW_LOCALHOST_ORIGINS=true.
        let staging = StaffChallengeOrigins::from_values(
            Some(&format!("https://account.staging.synvya.com,{local}")),
            "production",
            true,
        )
        .unwrap();
        assert!(staging.allows(local));
        assert!(staging.allows("https://account.staging.synvya.com"));
    }

    #[test]
    fn an_http_entry_names_a_local_host() {
        for ok in [
            "http://localhost:5273",
            "http://account.local.synvya.com:5273",
        ] {
            assert!(
                StaffChallengeOrigins::from_values(Some(ok), "production", true).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "http://account.synvya.com",
            "http://evil.example:5273",
            "http://local.synvya.com.evil.example",
        ] {
            assert!(
                StaffChallengeOrigins::from_values(Some(bad), "production", true).is_err(),
                "{bad} should be refused"
            );
            assert!(
                StaffChallengeOrigins::from_values(Some(bad), "development", false).is_err(),
                "{bad} should be refused off a deployment too"
            );
        }
    }

    #[test]
    fn refuses_a_path_a_wildcard_and_another_scheme() {
        for bad in [
            "https://account.synvya.com/app",
            "https://account.synvya.com/",
            "https://*.synvya.com",
            "ftp://account.synvya.com",
            "account.synvya.com",
        ] {
            assert!(
                StaffChallengeOrigins::from_values(Some(bad), "development", false).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn the_event_has_exactly_the_four_tags() {
        let req = StaffChallengeRequest {
            challenge_id: "c1".into(),
            nonce: "n1".into(),
            expires_at: "2026-11-18T19:00:00.000Z".into(),
        };
        let person = "b7".repeat(32);
        let tags: Vec<Vec<String>> = staff_challenge_tags(&req, &person)
            .into_iter()
            .map(|t| t.to_vec())
            .collect();
        assert_eq!(
            tags,
            vec![
                vec!["challenge_id".to_string(), "c1".to_string()],
                vec!["nonce".to_string(), "n1".to_string()],
                vec!["person_pubkey".to_string(), person.clone()],
                vec![
                    "expires_at".to_string(),
                    "2026-11-18T19:00:00.000Z".to_string()
                ],
            ]
        );
    }

    #[test]
    fn values_are_bounded() {
        assert!(check_value("nonce", "abc").is_ok());
        assert!(check_value("nonce", "").is_err());
        assert!(check_value("nonce", "a b").is_err());
        assert!(check_value("nonce", &"a".repeat(129)).is_err());
    }
}
