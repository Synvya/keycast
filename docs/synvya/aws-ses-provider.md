# AWS SES Email Provider — v1.0

Implement an `SesEmailSender` struct in `api/src/email_service.rs` as an alternative to the existing SendGrid email provider. This is an upstream-contributable feature — no Synvya-specific code.

**Architecture context**: See [Synvya Architecture](architecture-context.md) for how Keycast fits into the Synvya platform.

## 1. Problem Statement

Keycast sends three types of transactional emails:

1. **Email verification** — sent during registration, contains a link with a verification token
2. **Password reset** — sent via forgot-password flow, contains a reset link
3. **Claim email** — sent to preloaded/migrated accounts, contains a claim link

The current production implementation uses SendGrid's HTTP API v3. The email provider is selected implicitly: if `SENDGRID_API_KEY` is set, use SendGrid; otherwise, fall back to the `DevEmailSender` that logs to console.

Synvya's infrastructure runs on AWS. Using SendGrid requires a separate vendor relationship and API key management. AWS SES is included in the AWS ecosystem, integrates with IAM roles, and is significantly cheaper for transactional email.

## 2. Goals and Non-Goals

### 2.1 Goals

- Implement `SesEmailSender` using the AWS SDK for Rust (`aws-sdk-ses` v2 API)
- Reuse the exact same HTML/text email templates currently hardcoded in the SendGrid implementation
- Add provider selection via `EMAIL_PROVIDER` env var (`sendgrid`, `ses`, `dev`) replacing the implicit SendGrid detection
- Maintain backward compatibility: `SENDGRID_API_KEY` without `EMAIL_PROVIDER` still selects SendGrid
- Gate the AWS SDK dependency behind the same `aws` Cargo feature flag used by the KMS provider
- Support IAM role-based authentication (no API keys needed on EC2)

### 2.2 Non-Goals

- Does NOT change the `EmailSender` trait interface
- Does NOT change email content, subjects, or templates
- Does NOT add new email types
- Does NOT implement SES domain verification or DKIM setup (operational tasks)
- Does NOT replace the `DevEmailSender` — it remains the default for development

## 3. Current State

### 3.1 EmailSender Trait

`api/src/email_service.rs`:
```rust
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), String>;
    async fn send_password_reset_email(&self, to_email: &str, reset_token: &str) -> Result<(), String>;
    async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String>;
    fn get_captured_emails(&self) -> Vec<CapturedEmail>;
    fn clear_captured_emails(&self);
}
```

### 3.2 SendGrid Implementation

`SendGridEmailSender` sends emails via `POST https://api.sendgrid.com/v3/mail/send` using `reqwest`. Key details:

- Templates are hardcoded HTML/text strings in Rust (not external template files)
- Click tracking and open tracking are **disabled** for security-sensitive emails
- From address configurable via `FROM_EMAIL` (default: `noreply@divine.video`) and `FROM_NAME` (default: `Synvya`)
- Base URL for links configurable via `BASE_URL` (verification/reset) and `APP_URL` (claim)
- Brand color: `#00B488`

### 3.3 Provider Selection

`api/src/email_service.rs` (lines 479–487):
```rust
pub fn create_email_sender() -> Arc<dyn EmailSender> {
    match env::var("SENDGRID_API_KEY") {
        Ok(api_key) if !api_key.is_empty() => Arc::new(SendGridEmailSender::new(api_key)),
        _ => {
            tracing::warn!("SENDGRID_API_KEY not set - using development email sender");
            Arc::new(DevEmailSender::new())
        }
    }
}
```

### 3.4 Email Usage Locations

| Location | Method | When |
|---|---|---|
| `api/src/api/http/auth.rs` (register) | `send_verification_email` | New user registration |
| `api/src/api/http/auth.rs` (resend) | `send_verification_email` | User requests resend |
| `api/src/api/http/auth.rs` (forgot_password) | `send_password_reset_email` | Password reset request |
| `api/src/api/http/admin.rs` (batch_create_claim_tokens) | `send_claim_email` | Admin batch migration |
| `api/src/api/http/headless.rs` (register) | `send_verification_email` | Headless registration |

## 4. Implementation

### 4.1 Template Extraction

Before adding SES, extract the HTML/text template strings into shared functions so both SendGrid and SES use the same templates:

```rust
// Shared template functions (not provider-specific)
fn verification_email_html(verification_url: &str) -> String { /* existing HTML */ }
fn verification_email_text(verification_url: &str) -> String { /* existing text */ }
fn password_reset_html(reset_url: &str) -> String { /* existing HTML */ }
fn password_reset_text(reset_url: &str) -> String { /* existing text */ }
fn claim_email_html(claim_url: &str) -> String { /* existing HTML */ }
fn claim_email_text(claim_url: &str) -> String { /* existing text */ }
```

Update `SendGridEmailSender` to call these shared functions instead of inlining templates.

### 4.2 SesEmailSender Struct

```rust
#[cfg(feature = "aws")]
use aws_sdk_sesv2::Client as SesClient;

#[cfg(feature = "aws")]
pub struct SesEmailSender {
    client: SesClient,
    from_email: String,
    from_name: String,
    base_url: String,
    app_url: String,
}
```

### 4.3 Initialization

```rust
#[cfg(feature = "aws")]
impl SesEmailSender {
    pub async fn new() -> Result<Self, String> {
        let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .load()
            .await;

        let client = SesClient::new(&config);

        let from_email = env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@divine.video".to_string());
        let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Synvya".to_string());
        let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:5173".to_string());
        let app_url = env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        info!("AWS SES email sender initialized (region: {}, from: {})", region, from_email);

        Ok(Self { client, from_email, from_name, base_url, app_url })
    }
}
```

### 4.4 Sending Emails

Each `send_*` method follows the same pattern. Example for verification:

```rust
async fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), String> {
    let verification_url = format!("{}/verify-email?token={}", self.base_url, verification_token);
    let subject = "Verify your email address";
    let html = verification_email_html(&verification_url);
    let text = verification_email_text(&verification_url);

    self.send_email(to_email, subject, &html, &text).await
}
```

The shared `send_email` helper:

```rust
async fn send_email(&self, to: &str, subject: &str, html: &str, text: &str) -> Result<(), String> {
    let from = format!("{} <{}>", self.from_name, self.from_email);

    self.client.send_email()
        .from_email_address(&from)
        .destination(
            Destination::builder()
                .to_addresses(to)
                .build()
        )
        .content(
            EmailContent::builder()
                .simple(
                    Message::builder()
                        .subject(Content::builder().data(subject).charset("UTF-8").build())
                        .body(
                            Body::builder()
                                .html(Content::builder().data(html).charset("UTF-8").build())
                                .text(Content::builder().data(text).charset("UTF-8").build())
                                .build()
                        )
                        .build()
                )
                .build()
        )
        .send()
        .await
        .map_err(|e| format!("SES send failed: {}", e))?;

    debug!("Email sent to {} via SES", to);
    Ok(())
}
```

### 4.5 Cargo Feature Flag

In `api/Cargo.toml`:

```toml
[features]
aws = ["aws-sdk-sesv2", "aws-config"]

[dependencies]
aws-sdk-sesv2 = { version = "1", optional = true }
aws-config = { version = "1", features = ["behavior-version-latest"], optional = true }
```

If the `aws` feature is already shared with `keycast_core` via workspace, ensure `aws-config` is shared rather than duplicated. The `aws-config` crate should appear once in the workspace `[dependencies]` and be referenced by both `core` and `api`.

In `keycast/Cargo.toml`, extend the feature:

```toml
[features]
aws = ["keycast_core/aws", "keycast_api/aws"]
```

### 4.6 Provider Selection

Replace `create_email_sender()`:

```rust
pub fn create_email_sender() -> Arc<dyn EmailSender> {
    let provider = env::var("EMAIL_PROVIDER").unwrap_or_else(|_| {
        // Backward compatibility: SENDGRID_API_KEY presence → "sendgrid"
        if env::var("SENDGRID_API_KEY").map(|k| !k.is_empty()).unwrap_or(false) {
            "sendgrid".to_string()
        } else {
            "dev".to_string()
        }
    });

    match provider.as_str() {
        "sendgrid" => {
            let api_key = env::var("SENDGRID_API_KEY")
                .expect("SENDGRID_API_KEY must be set when EMAIL_PROVIDER=sendgrid");
            tracing::info!("Using SendGrid for email delivery");
            Arc::new(SendGridEmailSender::new(api_key))
        }
        #[cfg(feature = "aws")]
        "ses" => {
            tracing::info!("Using AWS SES for email delivery");
            // SesEmailSender::new() is async, but create_email_sender is sync.
            // Use tokio::runtime::Handle to block on initialization.
            let rt = tokio::runtime::Handle::current();
            let sender = rt.block_on(async { SesEmailSender::new().await })
                .expect("Failed to initialize AWS SES email sender");
            Arc::new(sender)
        }
        "dev" | _ => {
            tracing::warn!("Using development email sender (emails logged to console)");
            Arc::new(DevEmailSender::new())
        }
    }
}
```

**Note**: If `create_email_sender()` can be made async, prefer that over `block_on`. Check call sites — if they're already in async context, change the signature.

## 5. Environment Variables

### 5.1 New

| Variable | Required | Default | Description |
|---|---|---|---|
| `EMAIL_PROVIDER` | No | auto-detect | Email provider: `sendgrid`, `ses`, or `dev` |
| `AWS_REGION` | When `ses` | `us-east-1` | AWS region for SES (shared with KMS) |

AWS credentials are handled by the SDK default credential chain (same as KMS).

### 5.2 Unchanged

| Variable | Description |
|---|---|
| `SENDGRID_API_KEY` | Still used when `EMAIL_PROVIDER=sendgrid` |
| `FROM_EMAIL` | Sender address (shared across providers) |
| `FROM_NAME` | Sender name (shared across providers) |
| `BASE_URL` | Frontend URL for verification/reset links |
| `APP_URL` | API URL for claim links |
| `DISABLE_EMAILS` | Skips email sending entirely (shared across providers) |

## 6. AWS SES Setup

One-time setup for the Synvya deployment:

1. **Verify the sender domain** in SES (e.g., `synvya.com`)
2. **Request production access** — SES starts in sandbox mode (can only send to verified addresses)
3. **Configure DKIM** — SES provides DNS records to add to the domain

The EC2 instance's IAM role needs `ses:SendEmail` permission.

```json
{
  "Effect": "Allow",
  "Action": "ses:SendEmail",
  "Resource": "arn:aws:ses:us-east-1:ACCOUNT_ID:identity/synvya.com"
}
```

## 7. Testing

### 7.1 Unit Tests

| Test | Verifies |
|---|---|
| Template extraction | Shared HTML/text functions produce identical output to current inline templates |
| Provider selection: no env vars | Falls back to `DevEmailSender` |
| Provider selection: `SENDGRID_API_KEY` set | Selects SendGrid (backward compat) |
| Provider selection: `EMAIL_PROVIDER=ses` | Selects SES |
| Provider selection: `EMAIL_PROVIDER=sendgrid` overrides | Uses SendGrid even without `SENDGRID_API_KEY` detection |
| `DISABLE_EMAILS` flag | Email send is skipped regardless of provider |

### 7.2 Integration Tests

Gated behind SES access (skip if not in AWS):

| Test | Verifies |
|---|---|
| Send verification email | SES accepts the request, no errors |
| Send password reset email | SES accepts the request |
| Send claim email | SES accepts the request |

**Note**: Integration tests require a verified sender domain in SES and a verified recipient (or production access). Use a dedicated test email address.

## 8. Files Changed

| File | Change |
|---|---|
| `api/src/email_service.rs` | Extract templates to shared functions. Add `SesEmailSender` (gated behind `aws` feature). Replace `create_email_sender()` with `EMAIL_PROVIDER` selection. |
| `api/Cargo.toml` | Add `aws` feature flag with `aws-sdk-sesv2` and `aws-config` deps |
| `keycast/Cargo.toml` | Extend `aws` feature to include `keycast_api/aws` |

## 9. Upstream Contribution Notes

This is intended as a PR to `divinevideo/keycast` (can be combined with the KMS PR or separate). To keep it contributable:

- No Synvya-specific code (templates remain unchanged with existing branding)
- Feature-gated so it doesn't affect existing SendGrid deployments
- Backward-compatible: `SENDGRID_API_KEY` auto-detection still works
- Template extraction is a pure refactor that benefits the codebase regardless of SES
- The `EMAIL_PROVIDER` env var generalizes beyond SendGrid vs SES — future providers (Mailgun, SMTP) slot in the same way
