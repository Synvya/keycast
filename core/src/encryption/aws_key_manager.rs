// ABOUTME: AWS KMS key manager implementation for secure key encryption
// ABOUTME: Uses AWS KMS symmetric encryption for data encryption keys

use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client as KmsClient;
use std::env;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// Maximum retry attempts for KMS operations before failing.
const MAX_KMS_RETRIES: u32 = 3;

/// Base delay for exponential backoff (doubles each attempt: 100ms, 200ms, 400ms).
const KMS_BASE_DELAY_MS: u64 = 100;

pub struct AwsKeyManager {
    client: KmsClient,
    key_id: String,
}

impl std::fmt::Debug for AwsKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKeyManager")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl AwsKeyManager {
    pub async fn new() -> Result<Self, KeyManagerError> {
        let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let key_id = env::var("AWS_KMS_KEY_ID").map_err(|_| {
            KeyManagerError::ConfigurationError("AWS_KMS_KEY_ID not set".to_string())
        })?;

        Self::from_config(&region, &key_id).await
    }

    pub async fn from_config(region: &str, key_id: &str) -> Result<Self, KeyManagerError> {
        info!("Initializing AWS KMS client");
        debug!("Region: {}, Key ID: {}", region, key_id);

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;

        let client = KmsClient::new(&config);

        info!("AWS KMS client initialized successfully");

        Ok(Self {
            client,
            key_id: key_id.to_string(),
        })
    }
}

#[async_trait]
impl KeyManager for AwsKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        debug!("Encrypting {} bytes with AWS KMS", plaintext_bytes.len());

        let blob = Blob::new(plaintext_bytes);

        let mut attempt = 0u32;
        let response = loop {
            attempt += 1;
            match self
                .client
                .encrypt()
                .key_id(&self.key_id)
                .plaintext(blob.clone())
                .send()
                .await
            {
                Ok(resp) => break resp,
                Err(e) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        delay_ms = delay_ms,
                        "KMS encrypt failed, retrying: {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    error!("KMS encrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::EncryptionError(format!(
                        "AWS KMS encryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
            }
        };

        let ciphertext = response
            .ciphertext_blob()
            .ok_or_else(|| {
                KeyManagerError::EncryptionError("No ciphertext in response".to_string())
            })?
            .as_ref()
            .to_vec();

        debug!("Successfully encrypted to {} bytes", ciphertext.len());
        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        debug!("Decrypting {} bytes with AWS KMS", ciphertext_bytes.len());

        let blob = Blob::new(ciphertext_bytes);

        let mut attempt = 0u32;
        let response = loop {
            attempt += 1;
            match self
                .client
                .decrypt()
                .key_id(&self.key_id)
                .ciphertext_blob(blob.clone())
                .send()
                .await
            {
                Ok(resp) => break resp,
                Err(e) if attempt < MAX_KMS_RETRIES => {
                    let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    warn!(
                        attempt = attempt,
                        max_retries = MAX_KMS_RETRIES,
                        delay_ms = delay_ms,
                        "KMS decrypt failed, retrying: {}",
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    error!("KMS decrypt failed after {} attempts: {}", attempt, e);
                    return Err(KeyManagerError::DecryptionError(format!(
                        "AWS KMS decryption failed after {} attempts: {}",
                        attempt, e
                    )));
                }
            }
        };

        let plaintext = response
            .plaintext()
            .ok_or_else(|| {
                KeyManagerError::DecryptionError("No plaintext in response".to_string())
            })?
            .as_ref()
            .to_vec();

        debug!("Successfully decrypted to {} bytes", plaintext.len());
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_missing_key_id() {
        // Ensure AWS_KMS_KEY_ID is not set
        std::env::remove_var("AWS_KMS_KEY_ID");

        let result = AwsKeyManager::new().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            KeyManagerError::ConfigurationError(msg) => {
                assert!(msg.contains("AWS_KMS_KEY_ID"));
            }
            other => panic!("Expected ConfigurationError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // Skip test if AWS credentials not available
        if env::var("AWS_KMS_KEY_ID").is_err() {
            return;
        }

        let manager = AwsKeyManager::new()
            .await
            .expect("Failed to create AWS key manager");
        let plaintext = b"test data for encryption";

        let ciphertext = manager.encrypt(plaintext).await.expect("Encryption failed");
        let decrypted = manager
            .decrypt(&ciphertext)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_different_plaintexts_produce_different_ciphertexts() {
        if env::var("AWS_KMS_KEY_ID").is_err() {
            return;
        }

        let manager = AwsKeyManager::new()
            .await
            .expect("Failed to create AWS key manager");

        let ct1 = manager
            .encrypt(b"plaintext one")
            .await
            .expect("Encryption failed");
        let ct2 = manager
            .encrypt(b"plaintext two")
            .await
            .expect("Encryption failed");

        assert_ne!(ct1, ct2);
    }

    #[tokio::test]
    async fn test_large_payload() {
        if env::var("AWS_KMS_KEY_ID").is_err() {
            return;
        }

        let manager = AwsKeyManager::new()
            .await
            .expect("Failed to create AWS key manager");
        let plaintext = vec![0xABu8; 1024]; // 1KB payload

        let ciphertext = manager
            .encrypt(&plaintext)
            .await
            .expect("Encryption failed");
        let decrypted = manager
            .decrypt(&ciphertext)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
