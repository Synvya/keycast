#![cfg(feature = "aws")]

// ABOUTME: Integration tests for AWS SES email provider
// ABOUTME: Requires AWS credentials and a verified SES sender identity
// Tests skip gracefully if AWS_SES_TEST_RECIPIENT is not set

use keycast_api::email_service::SesEmailSender;
use keycast_api::email_service::EmailSender;

/// Skip helper: returns true if SES test env vars are available
fn ses_available() -> bool {
    std::env::var("AWS_SES_TEST_RECIPIENT").is_ok()
}

#[tokio::test]
async fn test_ses_initialization() {
    if !ses_available() {
        return;
    }

    // SES sender should initialize successfully with valid AWS credentials
    let sender = SesEmailSender::new().await;
    assert!(sender.is_ok(), "SES initialization failed: {:?}", sender.err());
}

#[tokio::test]
async fn test_ses_send_verification_email() {
    if !ses_available() {
        return;
    }

    let recipient = std::env::var("AWS_SES_TEST_RECIPIENT").unwrap();
    let sender = SesEmailSender::new().await.expect("SES init failed");

    let result = sender
        .send_verification_email(&recipient, "test-token-12345")
        .await;

    assert!(result.is_ok(), "Verification email failed: {:?}", result.err());
}

#[tokio::test]
async fn test_ses_send_password_reset_email() {
    if !ses_available() {
        return;
    }

    let recipient = std::env::var("AWS_SES_TEST_RECIPIENT").unwrap();
    let sender = SesEmailSender::new().await.expect("SES init failed");

    let result = sender
        .send_password_reset_email(&recipient, "reset-token-67890")
        .await;

    assert!(result.is_ok(), "Password reset email failed: {:?}", result.err());
}

#[tokio::test]
async fn test_ses_send_claim_email() {
    if !ses_available() {
        return;
    }

    let recipient = std::env::var("AWS_SES_TEST_RECIPIENT").unwrap();
    let sender = SesEmailSender::new().await.expect("SES init failed");

    let result = sender
        .send_claim_email(&recipient, "https://example.com/claim?token=abc123")
        .await;

    assert!(result.is_ok(), "Claim email failed: {:?}", result.err());
}

#[tokio::test]
async fn test_ses_disabled_emails_skips_send() {
    if !ses_available() {
        return;
    }

    let recipient = std::env::var("AWS_SES_TEST_RECIPIENT").unwrap();
    let sender = SesEmailSender::new().await.expect("SES init failed");

    // Set DISABLE_EMAILS to skip actual sending
    std::env::set_var("DISABLE_EMAILS", "1");

    let result = sender
        .send_verification_email(&recipient, "should-not-send")
        .await;

    std::env::remove_var("DISABLE_EMAILS");

    assert!(result.is_ok(), "Disabled send should succeed silently");
}
