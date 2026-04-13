use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Invitation expiry in days
pub const INVITATION_EXPIRY_DAYS: i64 = 7;

/// A pending, accepted, revoked, or expired team invitation
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TeamInvitation {
    pub id: i32,
    pub team_id: i32,
    pub tenant_id: i64,
    pub email: String,
    pub role: String,
    pub token: String,
    pub invited_by: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_by: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl TeamInvitation {
    /// Returns true if the invitation is still actionable.
    pub fn is_pending(&self) -> bool {
        self.accepted_at.is_none() && self.revoked_at.is_none() && self.expires_at > Utc::now()
    }
}

/// Public-facing invitation info returned by the list endpoint
#[derive(Debug, Serialize)]
pub struct InvitationListItem {
    pub id: i32,
    pub email: String,
    pub role: String,
    pub invited_by: String, // resolved to display name
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Public preview returned to unauthenticated users via token
#[derive(Debug, Serialize)]
pub struct InvitationPreview {
    pub team_name: String,
    pub role: String,
    pub invited_by_display_name: String,
    pub expires_at: DateTime<Utc>,
}

/// Generate a cryptographically random invitation token (32 bytes, hex-encoded = 64 chars)
pub fn generate_invitation_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_invitation_token_length() {
        let token = generate_invitation_token();
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_generate_invitation_token_uniqueness() {
        let t1 = generate_invitation_token();
        let t2 = generate_invitation_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_generate_invitation_token_is_hex() {
        let token = generate_invitation_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
