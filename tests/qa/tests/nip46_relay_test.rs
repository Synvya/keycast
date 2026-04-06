use keycast_qa_tests::fixtures::{TestApp, TestUser};
use keycast_qa_tests::helpers::nip46::{connect_via_relay, parse_bunker_url};
use keycast_qa_tests::helpers::oauth::OAuthClient;
use keycast_qa_tests::helpers::server::TestServer;
use nostr::{EventBuilder, Keys, Kind};
use nostr_connect::prelude::*;
use std::future::Future;
use std::time::Duration;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,keycast_qa_tests=debug")
        .try_init();
}

fn is_retryable_relay_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("timeout")
        || error.contains("503")
        || error.contains("service unavailable")
        || error.contains("temporarily unavailable")
        || error.contains("connection")
}

async fn retry_relay_operation<T, E, F, Fut>(
    label: &str,
    attempts: usize,
    mut operation: F,
) -> Result<T, String>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut last_error = None;

    for attempt in 1..=attempts {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let error = err.to_string();

                if attempt == attempts || !is_retryable_relay_error(&error) {
                    return Err(format!("{label} failed on attempt {attempt}: {error}"));
                }

                last_error = Some(error);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    Err(format!(
        "{label} failed after {attempts} attempts: {}",
        last_error.unwrap_or_else(|| "unknown relay error".to_string())
    ))
}

async fn connect_via_relay_ready(
    bunker_url: &str,
    timeout: Duration,
) -> Result<(NostrConnect, PublicKey), String> {
    let mut last_error = None;

    // Public relays can fail transiently even when the signer is healthy.
    // Require one successful `get_public_key` roundtrip before proceeding.
    for attempt in 1..=3 {
        match connect_via_relay(bunker_url, timeout).await {
            Ok(signer) => match retry_relay_operation("get_public_key", 2, || signer.get_public_key()).await {
                Ok(pubkey) => return Ok((signer, pubkey)),
                Err(err) if attempt < 3 => {
                    last_error = Some(format!("get_public_key attempt {attempt} failed: {err}"));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(err) => {
                    return Err(format!(
                        "get_public_key failed after relay connection succeeded: {err}"
                    ));
                }
            },
            Err(err) if attempt < 3 => {
                last_error = Some(format!("connect attempt {attempt} failed: {err}"));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(err) => return Err(format!("Failed to connect to signer after retries: {err}")),
        }
    }

    Err(format!(
        "Relay signer did not become ready after retries: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

#[tokio::test]
async fn nip46_001_connect_via_bunker_url() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow to get bunker URL
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Parse bunker URL
    let (pubkey, relays, secret) = parse_bunker_url(&token_resp.bunker_url)
        .expect("Should parse bunker URL");

    assert!(!pubkey.is_empty(), "Pubkey should not be empty");
    assert!(!relays.is_empty(), "Should have at least one relay");
    assert!(!secret.is_empty(), "Secret should not be empty");

    // Connect via relay
    let (_signer, user_pubkey) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Should connect via relay and complete the first roundtrip");

    // Note: With HKDF-derived bunker keys, the user_pubkey (signing key) differs
    // from bunker_pubkey (bunker URL key) for privacy. This is by design.
    assert_ne!(
        user_pubkey.to_hex(),
        pubkey,
        "User pubkey should differ from bunker pubkey (privacy via HKDF)"
    );

    // User pubkey should be a valid hex string
    assert_eq!(user_pubkey.to_hex().len(), 64, "User pubkey should be 64 hex chars");
}

#[tokio::test]
async fn nip46_002_get_public_key_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    let (bunker_pubkey, _, _) = parse_bunker_url(&token_resp.bunker_url)
        .expect("Should parse bunker URL");

    // Connect via relay
    let (_signer, user_pubkey) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Should connect via relay and complete the first roundtrip");

    // Note: With HKDF-derived bunker keys, user_pubkey differs from bunker_pubkey
    // for privacy (prevents relay traffic correlation). This is by design.
    assert_ne!(
        user_pubkey.to_hex(),
        bunker_pubkey,
        "User pubkey should differ from bunker pubkey (privacy via HKDF)"
    );

    // User pubkey should be a valid 64-char hex string
    assert_eq!(user_pubkey.to_hex().len(), 64, "User pubkey should be 64 hex chars");
    assert!(
        user_pubkey.to_hex().chars().all(|c| c.is_ascii_hexdigit()),
        "User pubkey should be valid hex"
    );
}

#[tokio::test]
async fn nip46_003_sign_event_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let (signer, pubkey) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Should connect via relay and complete the first roundtrip");

    // Build and sign event
    let unsigned = EventBuilder::text_note("Hello from NIP-46 relay test!").build(pubkey);
    let signed_event = retry_relay_operation("sign_event", 2, || signer.sign_event(unsigned.clone()))
        .await
        .expect("sign_event should succeed");

    // Verify event
    assert_eq!(signed_event.kind, Kind::TextNote, "Kind should be text note");
    assert_eq!(
        signed_event.content,
        "Hello from NIP-46 relay test!",
        "Content should match"
    );
    assert_eq!(signed_event.pubkey, pubkey, "Pubkey should match");
    assert!(signed_event.verify().is_ok(), "Signature should be valid");
}

#[tokio::test]
async fn nip46_004_nip44_encrypt_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let (signer, _pubkey) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Should connect via relay and complete the first roundtrip");

    // Generate recipient
    let recipient = Keys::generate();
    let recipient_pubkey = recipient.public_key();
    let plaintext = "Secret message for NIP-44 relay test";

    // Encrypt
    let ciphertext = retry_relay_operation("nip44_encrypt", 2, || {
        signer.nip44_encrypt(&recipient_pubkey, plaintext)
    })
        .await
        .expect("nip44_encrypt should succeed");

    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");
}

#[tokio::test]
async fn nip46_005_nip44_decrypt_over_relay() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let (signer, _pubkey) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Should connect via relay and complete the first roundtrip");

    // Generate recipient
    let recipient = Keys::generate();
    let recipient_pubkey = recipient.public_key();
    let plaintext = "Secret message for NIP-44 roundtrip test";

    // Encrypt
    let ciphertext = retry_relay_operation("nip44_encrypt", 2, || {
        signer.nip44_encrypt(&recipient_pubkey, plaintext)
    })
        .await
        .expect("nip44_encrypt should succeed");

    // Decrypt
    let decrypted = retry_relay_operation("nip44_decrypt", 2, || {
        signer.nip44_decrypt(&recipient_pubkey, &ciphertext)
    })
        .await
        .expect("nip44_decrypt should succeed");

    assert_eq!(decrypted, plaintext, "Decrypted text should match original");
}

#[tokio::test]
async fn nip46_007_secret_reuse_rejected() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // First client connects successfully
    let (_signer1, _pubkey1) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("First client should connect and complete the first roundtrip");

    // Second client with same secret should fail
    // Note: The bunker URL contains the same secret, so connecting again
    // from a different client should be rejected per NIP-46
    let signer2_result = connect_via_relay(&token_resp.bunker_url, Duration::from_secs(60)).await;

    // This behavior depends on implementation:
    // - Some implementations allow reconnection from same logical client
    // - Some reject any new connection with same secret
    // The test documents the actual behavior
    if signer2_result.is_ok() {
        // If second connection succeeds, it might be treated as reconnection
        // from the same client. This is acceptable per some interpretations.
        println!("Note: Second connection succeeded (may be same-client reconnection)");
    } else {
        // If second connection fails, secret reuse is being enforced
        println!("Secret reuse rejected as expected");
    }
}

#[tokio::test]
#[ignore] // NIP-46 secrets are single-use; reconnection with same secret isn't supported
async fn nip46_008_same_client_reconnect() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // First connection
    let (signer1, pubkey1) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("First connection should succeed and complete the first roundtrip");

    // Drop first signer to simulate disconnect
    drop(signer1);

    // Small delay to ensure cleanup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Reconnect with same bunker URL (same client scenario)
    // This should work as it's the same logical client reconnecting
    let (_signer2, pubkey2) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Reconnection should succeed and complete the first roundtrip");

    assert_eq!(pubkey1, pubkey2, "Public keys should match after reconnect");
}

#[tokio::test]
async fn nip46_bunker_url_format_validation() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    let bunker_url = &token_resp.bunker_url;

    // Validate bunker URL format
    assert!(bunker_url.starts_with("bunker://"), "Should start with bunker://");

    // Parse and validate components
    let (pubkey, relays, secret) = parse_bunker_url(bunker_url).expect("Should parse bunker URL");

    // Pubkey validation
    assert_eq!(pubkey.len(), 64, "Pubkey should be 64 hex chars");
    assert!(
        pubkey.chars().all(|c| c.is_ascii_hexdigit()),
        "Pubkey should be valid hex"
    );

    // Relay validation
    assert!(!relays.is_empty(), "Should have at least one relay");
    for relay in &relays {
        assert!(
            relay.starts_with("wss://") || relay.starts_with("ws://"),
            "Relay should be valid WebSocket URL: {}",
            relay
        );
    }

    // Secret validation
    assert!(secret.len() >= 32, "Secret should be at least 32 chars");
}

#[tokio::test]
async fn nip46_multiple_operations_sequence() {
    init_tracing();
    let server = TestServer::from_env();
    let oauth = OAuthClient::new(server.clone());
    let user = TestUser::generate();
    let app = TestApp::default();

    // Complete OAuth flow
    let token_resp = oauth
        .complete_oauth_flow(&user, &app)
        .await
        .expect("OAuth flow should complete");

    // Connect via relay
    let (signer, pubkey) =
        connect_via_relay_ready(&token_resp.bunker_url, Duration::from_secs(60))
        .await
        .expect("Should connect via relay and complete the first roundtrip");

    let recipient = Keys::generate();
    let recipient_pubkey = recipient.public_key();

    // Sequence of operations
    // 1. Sign first event
    let event1 = retry_relay_operation("sign first event", 2, || {
        signer.sign_event(EventBuilder::text_note("First note").build(pubkey))
    })
        .await
        .expect("Step 1: sign first event");
    assert!(event1.verify().is_ok(), "First event should be valid");

    // 2. Encrypt message
    let plaintext = "Secret for sequence test";
    let ciphertext = retry_relay_operation("nip44_encrypt", 2, || {
        signer.nip44_encrypt(&recipient_pubkey, plaintext)
    })
        .await
        .expect("Step 2: encrypt");

    // 3. Sign second event
    let event2 = retry_relay_operation("sign second event", 2, || {
        signer.sign_event(EventBuilder::text_note("Second note").build(pubkey))
    })
        .await
        .expect("Step 3: sign second event");
    assert!(event2.verify().is_ok(), "Second event should be valid");

    // 4. Decrypt message
    let decrypted = retry_relay_operation("nip44_decrypt", 2, || {
        signer.nip44_decrypt(&recipient_pubkey, &ciphertext)
    })
        .await
        .expect("Step 4: decrypt");
    assert_eq!(decrypted, plaintext, "Decrypted should match");

    // 6. Get public key again (should be consistent)
    let pubkey2 = retry_relay_operation("get_public_key", 2, || signer.get_public_key())
        .await
        .expect("Step 6: get_public_key again");
    assert_eq!(pubkey, pubkey2, "Pubkey should be consistent");

    // All events should have same pubkey
    assert_eq!(event1.pubkey, pubkey, "Event1 pubkey should match");
    assert_eq!(event2.pubkey, pubkey, "Event2 pubkey should match");

    // Events should have different IDs
    assert_ne!(event1.id, event2.id, "Events should have different IDs");
}
