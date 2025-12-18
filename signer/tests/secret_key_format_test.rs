// Tests for secret key encryption/decryption format consistency
// Verifies that user secret keys are stored as raw encrypted bytes
// and can be correctly decrypted and parsed into Keys

use keycast_core::encryption::{file_key_manager::FileKeyManager, KeyManager};
use nostr_sdk::prelude::*;

/// Test that raw bytes format works correctly for stored secrets
/// Format: encrypt(secret_bytes) -> decrypt -> SecretKey::from_slice
#[tokio::test]
async fn test_secret_raw_bytes_format() {
    let key_manager = FileKeyManager::new().expect("Failed to create key manager");

    // Generate a user key
    let user_keys = Keys::generate();

    // Get raw 32-byte secret
    let secret_bytes = user_keys.secret_key().secret_bytes();
    assert_eq!(secret_bytes.len(), 32, "Secret key should be 32 bytes");

    // Encrypt the raw bytes (this is how secrets are stored)
    let encrypted = key_manager
        .encrypt(&secret_bytes)
        .await
        .expect("Failed to encrypt secret");

    // Decrypt and verify we can reconstruct the key
    let decrypted = key_manager
        .decrypt(&encrypted)
        .await
        .expect("Failed to decrypt secret");

    // Should be able to create SecretKey directly from decrypted bytes
    let recovered_secret = SecretKey::from_slice(&decrypted)
        .expect("Should be able to create SecretKey from raw bytes");
    let recovered_keys = Keys::new(recovered_secret);

    // Verify the public key matches
    assert_eq!(
        recovered_keys.public_key().to_hex(),
        user_keys.public_key().to_hex(),
        "Recovered key should match original"
    );
}
