//! Synvya: a signed-in person's own display name.
//!
//! `GET /api/user/display-name` answers `{"display_name": string | null}` for
//! the session's person. `PUT /api/user/display-name` with the same body sets
//! it: the value is trimmed, must then be 1 to 80 characters with no control
//! or bidirectional-override characters, and an empty or `null` value clears
//! it. The field is required, so a misspelled body cannot clear a name.
//!
//! The name is stored in `users.display_name`, which every team-member list
//! returns beside `email` (`TeamUser`, `BuyerTeamMember`), so a teammate can be
//! shown by name instead of by email.
//!
//! This file is Synvya-only and stays out of upstream code, so an upstream
//! merge does not touch it.

use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;

use super::auth::{extract_user_from_token, AuthError};
use crate::api::tenant::TenantExtractor;
use keycast_core::repositories::UserRepository;

/// The longest display name, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 80;

/// The body of `PUT /api/user/display-name`.
#[derive(Debug, Deserialize)]
pub struct SetDisplayNameRequest {
    /// `None` when the field is missing; `Some(None)` when it is `null`.
    #[serde(default, deserialize_with = "present")]
    pub display_name: Option<Option<String>>,
}

fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// The answer of both routes.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DisplayNameResponse {
    pub display_name: Option<String>,
}

/// Bidirectional override and isolate characters. They are format characters,
/// not control characters, but they can make a name read as another one.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The value to store for `raw`: `Ok(None)` clears the name.
pub fn normalize_display_name(raw: Option<&str>) -> Result<Option<String>, String> {
    let trimmed = match raw.map(str::trim) {
        None | Some("") => return Ok(None),
        Some(t) => t,
    };
    if trimmed.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(format!(
            "Display name must be at most {} characters",
            MAX_DISPLAY_NAME_CHARS
        ));
    }
    if trimmed
        .chars()
        .any(|c| c.is_control() || is_bidi_control(c))
    {
        return Err("Display name must not contain control characters".to_string());
    }
    Ok(Some(trimmed.to_string()))
}

/// `GET /api/user/display-name`
pub async fn get_display_name(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<DisplayNameResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let display_name = UserRepository::new(pool)
        .get_display_name(&pubkey, tenant_id)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    Ok(Json(DisplayNameResponse { display_name }))
}

/// `PUT /api/user/display-name`
pub async fn set_display_name(
    tenant: TenantExtractor,
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(req): Json<SetDisplayNameRequest>,
) -> Result<Json<DisplayNameResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    let pubkey = extract_user_from_token(&headers, tenant_id).await?;
    let raw = req
        .display_name
        .ok_or_else(|| AuthError::BadRequest("display_name is required".to_string()))?;
    let display_name = normalize_display_name(raw.as_deref()).map_err(AuthError::BadRequest)?;

    let updated = UserRepository::new(pool)
        .set_display_name(&pubkey, tenant_id, display_name.as_deref())
        .await?;
    if !updated {
        return Err(AuthError::UserNotFound);
    }
    Ok(Json(DisplayNameResponse { display_name }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_keeps_a_valid_name() {
        assert_eq!(
            normalize_display_name(Some("  Ana López ")),
            Ok(Some("Ana López".to_string()))
        );
    }

    #[test]
    fn empty_whitespace_and_null_clear_the_name() {
        assert_eq!(normalize_display_name(None), Ok(None));
        assert_eq!(normalize_display_name(Some("")), Ok(None));
        assert_eq!(normalize_display_name(Some(" \t ")), Ok(None));
    }

    #[test]
    fn counts_characters_not_bytes() {
        let at_limit = "é".repeat(MAX_DISPLAY_NAME_CHARS);
        assert_eq!(
            normalize_display_name(Some(&at_limit)),
            Ok(Some(at_limit.clone()))
        );
        let over = "a".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert!(normalize_display_name(Some(&over)).is_err());
    }

    #[test]
    fn refuses_control_and_bidi_characters() {
        assert!(normalize_display_name(Some("Ana\nLópez")).is_err());
        assert!(normalize_display_name(Some("Ana\u{0007}")).is_err());
        assert!(normalize_display_name(Some("Ana\u{202E}zepoL")).is_err());
    }

    #[test]
    fn the_field_is_required_but_may_be_null() {
        let missing: SetDisplayNameRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(missing.display_name, None);
        let null: SetDisplayNameRequest = serde_json::from_str(r#"{"display_name":null}"#).unwrap();
        assert_eq!(null.display_name, Some(None));
        let set: SetDisplayNameRequest = serde_json::from_str(r#"{"display_name":"Ana"}"#).unwrap();
        assert_eq!(set.display_name, Some(Some("Ana".to_string())));
    }
}
