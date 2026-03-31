# AWS KMS Encryption Provider — v1.0

Implement the `AwsKeyManager` struct in `core/src/encryption/aws_key_manager.rs` to provide AWS KMS as an alternative to the existing GCP KMS and file-based encryption providers. This is an upstream-contributable feature — no Synvya-specific code.

**Architecture context**: See [Synvya Architecture](architecture-context.md) for how Keycast fits into the Synvya platform.

## 1. Problem Statement

Keycast encrypts all stored private keys (team keys in `stored_keys`, personal keys in `personal_keys`) at rest using AES-256-GCM. The encryption key is managed by one of two providers selected at startup:

- **FileKeyManager**: Loads a base64-encoded 32-byte master key from disk. Suitable for development.
- **GcpKeyManager**: Delegates encrypt/decrypt to Google Cloud KMS. Used in production on Cloud Run.

Both implement the `KeyManager` trait (`core/src/encryption/mod.rs`):

```rust
#[async_trait]
pub trait KeyManager: Send + Sync {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError>;
    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError>;
}
```

An `AwsKeyManager` stub already exists at `core/src/encryption/aws_key_manager.rs` with `todo!()` placeholders. This spec defines the complete implementation.

## 2. Goals and Non-Goals

### 2.1 Goals

- Implement `AwsKeyManager` using the AWS SDK for Rust (`aws-sdk-kms`)
- Match the GCP provider's reliability pattern: exponential backoff retries (3 attempts, 100ms base)
- Gate the AWS SDK dependency behind a Cargo feature flag (`aws`) so it doesn't increase compile time or binary size for deployments that don't use it
- Add provider selection via `KMS_PROVIDER` env var (`file`, `gcp`, `aws`) replacing the boolean `USE_GCP_KMS`
- Maintain backward compatibility: `USE_GCP_KMS=true` continues to work during transition
- Add a roundtrip integration test gated behind AWS credentials

### 2.2 Non-Goals

- Does NOT change the `KeyManager` trait interface
- Does NOT change how encrypted data is stored in PostgreSQL (same bytea columns)
- Does NOT implement envelope encryption — AWS KMS handles encryption directly, same as GCP KMS
- Does NOT add AWS IAM role-based auth for other services (only KMS)

## 3. Current State

### 3.1 Existing Stub

`core/src/encryption/aws_key_manager.rs`:
```rust
pub struct AwsKeyManager {
    // Add AWS KMS client here
}

impl AwsKeyManager {
    pub async fn new() -> Result<Self, KeyManagerError> {
        todo!("Implement AWS KMS client initialization")
    }
}

#[async_trait]
impl KeyManager for AwsKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        todo!("Implement AWS KMS encryption")
    }
    async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        todo!("Implement AWS KMS decryption")
    }
}
```

### 3.2 GCP Reference Implementation

`core/src/encryption/gcp_key_manager.rs` — the pattern to follow:

1. `new()` reads env vars, initializes the SDK client, builds the full key resource name
2. `encrypt()` sends `EncryptRequest` with plaintext bytes, returns ciphertext bytes
3. `decrypt()` sends `DecryptRequest` with ciphertext bytes, returns `Zeroizing<Vec<u8>>`
4. Both methods retry up to 3 times with exponential backoff (100ms, 200ms, 400ms)
5. Uses `tracing` for structured logging at debug/warn/error levels

### 3.3 Provider Selection in main.rs

`keycast/src/main.rs` (lines 440–455):
```rust
let use_gcp_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";

let signer_key_manager: Box<dyn KeyManager> = if use_gcp_kms {
    Box::new(GcpKeyManager::new().await?)
} else {
    Box::new(FileKeyManager::new()?)
};
```

Two instances are created (one for signer, one for API). Both are stored as `Arc<Box<dyn KeyManager>>`.

### 3.4 Env Validation in main.rs

`keycast/src/main.rs` (lines 266–274):
```rust
let use_gcp_kms = env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true";
if !use_gcp_kms && env::var("MASTER_KEY_PATH").is_err() {
    errors.push("MASTER_KEY_PATH must be set when USE_GCP_KMS=false");
}
if use_gcp_kms && env::var("GCP_PROJECT_ID").is_err() {
    errors.push("GCP_PROJECT_ID must be set when USE_GCP_KMS=true");
}
```

## 4. Implementation

### 4.1 AwsKeyManager Struct

```rust
use aws_sdk_kms::Client as KmsClient;

pub struct AwsKeyManager {
    client: KmsClient,
    key_id: String,
}
```

### 4.2 Initialization

```rust
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

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
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
```

The `key_id` can be a key ARN, key ID, or alias ARN (e.g., `alias/keycast-master-key`). AWS SDK resolves all formats.

### 4.3 Encrypt

```rust
async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
    debug!("Encrypting {} bytes with AWS KMS", plaintext_bytes.len());

    let blob = Blob::new(plaintext_bytes);

    let mut attempt = 0u32;
    let response = loop {
        attempt += 1;
        match self.client.encrypt()
            .key_id(&self.key_id)
            .plaintext(blob.clone())
            .send()
            .await
        {
            Ok(resp) => break resp,
            Err(e) if attempt < MAX_KMS_RETRIES => {
                let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                warn!(attempt, max_retries = MAX_KMS_RETRIES, delay_ms, "KMS encrypt failed, retrying: {}", e);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Err(e) => {
                error!("KMS encrypt failed after {} attempts: {}", attempt, e);
                return Err(KeyManagerError::EncryptionError(
                    format!("AWS KMS encryption failed after {} attempts: {}", attempt, e),
                ));
            }
        }
    };

    let ciphertext = response.ciphertext_blob()
        .ok_or_else(|| KeyManagerError::EncryptionError("No ciphertext in response".to_string()))?
        .as_ref()
        .to_vec();

    debug!("Successfully encrypted to {} bytes", ciphertext.len());
    Ok(ciphertext)
}
```

### 4.4 Decrypt

```rust
async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
    debug!("Decrypting {} bytes with AWS KMS", ciphertext_bytes.len());

    let blob = Blob::new(ciphertext_bytes);

    let mut attempt = 0u32;
    let response = loop {
        attempt += 1;
        match self.client.decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(blob.clone())
            .send()
            .await
        {
            Ok(resp) => break resp,
            Err(e) if attempt < MAX_KMS_RETRIES => {
                let delay_ms = KMS_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                warn!(attempt, max_retries = MAX_KMS_RETRIES, delay_ms, "KMS decrypt failed, retrying: {}", e);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Err(e) => {
                error!("KMS decrypt failed after {} attempts: {}", attempt, e);
                return Err(KeyManagerError::DecryptionError(
                    format!("AWS KMS decryption failed after {} attempts: {}", attempt, e),
                ));
            }
        }
    };

    let plaintext = response.plaintext()
        .ok_or_else(|| KeyManagerError::DecryptionError("No plaintext in response".to_string()))?
        .as_ref()
        .to_vec();

    debug!("Successfully decrypted to {} bytes", plaintext.len());
    Ok(Zeroizing::new(plaintext))
}
```

### 4.5 Cargo Feature Flag

In `core/Cargo.toml`:

```toml
[features]
integration-tests = []
aws = ["aws-sdk-kms", "aws-config"]

[dependencies]
# ... existing deps ...
aws-sdk-kms = { version = "1", optional = true }
aws-config = { version = "1", features = ["behavior-version-latest"], optional = true }
```

Gate the module in `core/src/encryption/mod.rs`:

```rust
#[cfg(feature = "aws")]
pub mod aws_key_manager;
pub mod file_key_manager;
pub mod gcp_key_manager;
```

In `keycast/Cargo.toml`, add:

```toml
[features]
default = []
aws = ["keycast_core/aws"]
```

### 4.6 Provider Selection (main.rs)

Replace the boolean `USE_GCP_KMS` check with a `KMS_PROVIDER` enum:

```rust
let kms_provider = env::var("KMS_PROVIDER")
    .or_else(|_| {
        // Backward compatibility: USE_GCP_KMS=true → "gcp"
        if env::var("USE_GCP_KMS").unwrap_or_default() == "true" {
            Ok("gcp".to_string())
        } else {
            Ok("file".to_string())
        }
    })
    .unwrap();

let signer_key_manager: Box<dyn KeyManager> = match kms_provider.as_str() {
    "gcp" => {
        tracing::info!("Using Google Cloud KMS for encryption");
        Box::new(GcpKeyManager::new().await?)
    }
    #[cfg(feature = "aws")]
    "aws" => {
        tracing::info!("Using AWS KMS for encryption");
        Box::new(AwsKeyManager::new().await?)
    }
    "file" | _ => {
        tracing::info!("Using file-based encryption");
        Box::new(FileKeyManager::new()?)
    }
};
```

Update env validation to match:

```rust
match kms_provider.as_str() {
    "file" => {
        if env::var("MASTER_KEY_PATH").is_err() {
            errors.push("MASTER_KEY_PATH must be set when KMS_PROVIDER=file");
        }
    }
    "gcp" => {
        if env::var("GCP_PROJECT_ID").is_err() {
            errors.push("GCP_PROJECT_ID must be set when KMS_PROVIDER=gcp");
        }
    }
    "aws" => {
        if env::var("AWS_KMS_KEY_ID").is_err() {
            errors.push("AWS_KMS_KEY_ID must be set when KMS_PROVIDER=aws");
        }
    }
    _ => errors.push("KMS_PROVIDER must be 'file', 'gcp', or 'aws'"),
}
```

## 5. Environment Variables

### 5.1 New

| Variable | Required | Default | Description |
|---|---|---|---|
| `KMS_PROVIDER` | No | `file` | Encryption provider: `file`, `gcp`, or `aws` |
| `AWS_KMS_KEY_ID` | When `KMS_PROVIDER=aws` | — | AWS KMS key ID, ARN, or alias ARN |
| `AWS_REGION` | No | `us-east-1` | AWS region for KMS |

AWS credentials (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` or IAM role) are handled by the AWS SDK default credential chain — no Keycast-specific config needed.

### 5.2 Deprecated

| Variable | Replacement |
|---|---|
| `USE_GCP_KMS` | `KMS_PROVIDER=gcp` (backward-compatible: `USE_GCP_KMS=true` still works) |

## 6. AWS KMS Key Setup

One-time setup for the Synvya deployment:

```bash
aws kms create-key \
  --description "Keycast master encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --region us-east-1

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/keycast-master-key \
  --target-key-id <key-id> \
  --region us-east-1
```

The EC2 instance's IAM role needs `kms:Encrypt` and `kms:Decrypt` permissions on this key.

## 7. Data Migration

When migrating from file-based or GCP KMS to AWS KMS, existing encrypted data must be re-encrypted. This is a one-time migration:

1. Read all rows from `stored_keys` and `personal_keys`
2. Decrypt each `secret_key` / `encrypted_secret_key` using the old provider
3. Re-encrypt using the new provider
4. Update the row

This should be implemented as a standalone migration script (not part of this PR). The script needs access to both the old and new key managers simultaneously.

## 8. Testing

### 8.1 Unit Tests

| Test | Verifies |
|---|---|
| `AwsKeyManager::new()` with missing `AWS_KMS_KEY_ID` | Returns `ConfigurationError` |
| Retry logic | Retries on transient errors, stops at max retries |
| Empty ciphertext response | Returns `EncryptionError` |
| Provider selection fallback | `USE_GCP_KMS=true` still selects GCP provider |
| `KMS_PROVIDER=aws` without feature flag | Compilation error or runtime error with clear message |

### 8.2 Integration Tests

Gated behind AWS credentials (skip if `AWS_KMS_KEY_ID` not set):

| Test | Verifies |
|---|---|
| Encrypt-decrypt roundtrip | Plaintext → encrypt → decrypt → same plaintext |
| Different plaintexts produce different ciphertexts | Non-deterministic encryption |
| Large payload (1KB) | Handles payloads larger than typical 32-byte keys |

## 9. Files Changed

| File | Change |
|---|---|
| `core/src/encryption/aws_key_manager.rs` | Replace `todo!()` stubs with full implementation |
| `core/src/encryption/mod.rs` | Gate `aws_key_manager` behind `#[cfg(feature = "aws")]` |
| `core/Cargo.toml` | Add `aws` feature flag with `aws-sdk-kms` and `aws-config` deps |
| `keycast/Cargo.toml` | Add `aws` feature flag forwarding to `keycast_core/aws` |
| `keycast/src/main.rs` | Replace `USE_GCP_KMS` boolean with `KMS_PROVIDER` enum selection |

## 10. Upstream Contribution Notes

This is intended as a PR to `divinevideo/keycast`. To keep it contributable:

- No Synvya-specific code (no domain references, no Synvya env vars)
- Feature-gated so it doesn't affect existing GCP deployments
- Backward-compatible: `USE_GCP_KMS=true` keeps working
- Follows the exact same patterns as the GCP implementation (retry logic, logging, error handling)
- The `KMS_PROVIDER` env var generalizes beyond just GCP vs AWS — future providers slot in the same way
