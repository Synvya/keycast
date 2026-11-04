// ABOUTME: Bounded cache of decrypted keys in front of a KeyManager, to reduce paid KMS calls
// ABOUTME: Keyed by ciphertext, so stored data does not change and the cache can be removed at any time

use super::{KeyManager, KeyManagerError};
use async_trait::async_trait;
use moka::future::Cache;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// How long a decrypted key stays in memory after it was last decrypted.
const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);
/// How many decrypted keys to hold.
const DEFAULT_CAPACITY: u64 = 100_000;

/// Serves repeat decrypts of the same ciphertext from memory for a bounded time.
///
/// Encrypt always goes to the inner manager, because each call must produce new ciphertext.
/// Plaintext is zeroized when an entry is dropped.
pub struct CachingKeyManager {
    inner: Box<dyn KeyManager>,
    cache: Cache<[u8; 32], Arc<Zeroizing<Vec<u8>>>>,
}

impl CachingKeyManager {
    pub fn new(inner: Box<dyn KeyManager>) -> Self {
        Self::with_limits(inner, DEFAULT_TTL, DEFAULT_CAPACITY)
    }

    pub fn with_limits(inner: Box<dyn KeyManager>, ttl: Duration, capacity: u64) -> Self {
        Self {
            inner,
            cache: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(ttl)
                .build(),
        }
    }

    fn cache_key(ciphertext_bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(ciphertext_bytes).into()
    }
}

#[async_trait]
impl KeyManager for CachingKeyManager {
    async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let ciphertext = self.inner.encrypt(plaintext_bytes).await?;

        // A key that was just encrypted is usually used straight away
        self.cache
            .insert(
                Self::cache_key(&ciphertext),
                Arc::new(Zeroizing::new(plaintext_bytes.to_vec())),
            )
            .await;

        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
        // try_get_with shares one inner call between concurrent decrypts of the same key,
        // and does not cache a failure
        let plaintext = self
            .cache
            .try_get_with(Self::cache_key(ciphertext_bytes), async {
                self.inner.decrypt(ciphertext_bytes).await.map(Arc::new)
            })
            .await
            .map_err(|e| KeyManagerError::Decrypt(format!("{e:?}")))?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Calls {
        encrypts: AtomicUsize,
        decrypts: AtomicUsize,
        failing: AtomicBool,
    }

    /// Reverses bytes, so ciphertext differs from plaintext, and counts calls.
    struct CountingManager(Arc<Calls>);

    #[async_trait]
    impl KeyManager for CountingManager {
        async fn encrypt(&self, plaintext_bytes: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
            self.0.encrypts.fetch_add(1, Ordering::SeqCst);
            Ok(plaintext_bytes.iter().rev().copied().collect())
        }

        async fn decrypt(
            &self,
            ciphertext_bytes: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, KeyManagerError> {
            self.0.decrypts.fetch_add(1, Ordering::SeqCst);
            if self.0.failing.load(Ordering::SeqCst) {
                return Err(KeyManagerError::Decrypt("KMS unavailable".to_string()));
            }
            Ok(Zeroizing::new(
                ciphertext_bytes.iter().rev().copied().collect(),
            ))
        }
    }

    fn manager() -> (CachingKeyManager, Arc<Calls>) {
        let calls = Arc::new(Calls::default());
        let manager = CachingKeyManager::new(Box::new(CountingManager(calls.clone())));
        (manager, calls)
    }

    #[tokio::test]
    async fn test_repeat_decrypts_reach_the_inner_manager_once() {
        let (manager, calls) = manager();

        for _ in 0..5 {
            assert_eq!(manager.decrypt(b"cba").await.unwrap().as_slice(), b"abc");
        }

        assert_eq!(calls.decrypts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_different_ciphertexts_do_not_share_an_entry() {
        let (manager, calls) = manager();

        assert_eq!(manager.decrypt(b"cba").await.unwrap().as_slice(), b"abc");
        assert_eq!(manager.decrypt(b"fed").await.unwrap().as_slice(), b"def");

        assert_eq!(calls.decrypts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_a_key_just_encrypted_needs_no_decrypt() {
        let (manager, calls) = manager();

        let ciphertext = manager.encrypt(b"abc").await.unwrap();
        assert_eq!(
            manager.decrypt(&ciphertext).await.unwrap().as_slice(),
            b"abc"
        );

        assert_eq!(calls.encrypts.load(Ordering::SeqCst), 1);
        assert_eq!(calls.decrypts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_every_encrypt_reaches_the_inner_manager() {
        let (manager, calls) = manager();

        manager.encrypt(b"abc").await.unwrap();
        manager.encrypt(b"abc").await.unwrap();

        assert_eq!(calls.encrypts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_a_failure_is_not_cached() {
        let (manager, calls) = manager();

        calls.failing.store(true, Ordering::SeqCst);
        assert!(manager.decrypt(b"cba").await.is_err());

        calls.failing.store(false, Ordering::SeqCst);
        assert_eq!(manager.decrypt(b"cba").await.unwrap().as_slice(), b"abc");
        assert_eq!(calls.decrypts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_concurrent_decrypts_share_one_inner_call() {
        let (manager, calls) = manager();
        let manager = Arc::new(manager);

        let mut tasks = Vec::new();
        for _ in 0..20 {
            let manager = manager.clone();
            tasks.push(tokio::spawn(async move { manager.decrypt(b"cba").await }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().as_slice(), b"abc");
        }

        assert_eq!(calls.decrypts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_entries_expire() {
        let calls = Arc::new(Calls::default());
        let manager = CachingKeyManager::with_limits(
            Box::new(CountingManager(calls.clone())),
            Duration::from_millis(50),
            10,
        );

        manager.decrypt(b"cba").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        manager.decrypt(b"cba").await.unwrap();

        assert_eq!(calls.decrypts.load(Ordering::SeqCst), 2);
    }
}
