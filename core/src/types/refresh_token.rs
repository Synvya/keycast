use chrono::{DateTime, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::FromRow;

/// Refresh token lifetime in days (30 days fixed, not configurable)
pub const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 30;

/// OAuth refresh token for silent token renewal (RFC 6749 §6)
#[derive(Debug, FromRow)]
pub struct RefreshToken {
    pub id: i32,
    pub token_hash: String,
    pub authorization_id: i32,
    pub tenant_id: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// Generate a cryptographically random refresh token (256 bits / 64 hex chars)
pub fn generate_refresh_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Hash a refresh token for storage using SHA256
/// Uses SHA256 (not bcrypt) because refresh tokens need to be looked up by hash
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_refresh_token_length() {
        let token = generate_refresh_token();
        assert_eq!(token.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_generate_refresh_token_uniqueness() {
        let token1 = generate_refresh_token();
        let token2 = generate_refresh_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_hash_refresh_token() {
        let token = "abc123";
        let hash = hash_refresh_token(token);
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars

        // Same input should produce same hash
        let hash2 = hash_refresh_token(token);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_refresh_token_different_inputs() {
        let hash1 = hash_refresh_token("token1");
        let hash2 = hash_refresh_token("token2");
        assert_ne!(hash1, hash2);
    }
}
