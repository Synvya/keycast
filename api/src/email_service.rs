// ABOUTME: Email service abstraction for sending verification and password reset emails
// ABOUTME: Supports SendGrid for production, AWS SES (behind `aws` feature), and DevEmailSender for local development/testing

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::env;
use std::sync::{Arc, Mutex};

/// Captured email for testing/inspection
#[derive(Debug, Clone)]
pub struct CapturedEmail {
    pub to: String,
    pub subject: String,
    pub verification_url: Option<String>,
    pub reset_url: Option<String>,
}

/// Trait for email sending - allows swapping implementations for testing
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String>;
    /// Send the password reset email.
    ///
    /// `base_url_override`, when `Some`, is used as the link prefix
    /// instead of the implementor's configured `password_reset_base_url`.
    /// The handler is expected to validate the override against the
    /// CORS allowlist before passing it down (see
    /// `api/http/auth.rs::forgot_password`) — implementations here just
    /// trust the value.
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
        base_url_override: Option<&str>,
    ) -> Result<(), String>;

    /// Send a claim link email for a preloaded account.
    ///
    /// `account_display_name` and `account_picture` come from the preloaded
    /// pubkey's kind-0 metadata when available; when both are `None` the email
    /// falls back to the plain single-CTA layout.
    async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
        account_display_name: Option<&str>,
        account_picture: Option<&str>,
    ) -> Result<(), String>;

    /// Send a team invitation email.
    ///
    /// `team_display_name` should be the kind-0 display name when available,
    /// falling back to the DB team handle. `team_picture` is an optional kind-0
    /// avatar URL (http/https only; callers are responsible for validating).
    /// `inviter_label` is the admin's email (preferred) or display name.
    #[allow(clippy::too_many_arguments)]
    async fn send_team_invite_email(
        &self,
        to_email: &str,
        team_display_name: &str,
        team_picture: Option<&str>,
        inviter_label: &str,
        role: &str,
        expires_at: DateTime<Utc>,
        invite_url: &str,
    ) -> Result<(), String>;

    /// Get captured emails (only available in dev/test mode)
    fn get_captured_emails(&self) -> Vec<CapturedEmail> {
        vec![]
    }

    /// Clear captured emails (only available in dev/test mode)
    fn clear_captured_emails(&self) {
        // No-op by default
    }
}

/// Resolve the base URL used in password reset links.
///
/// Defaults to `BASE_URL` but may be overridden via `PASSWORD_RESET_BASE_URL`
/// when the password reset page is hosted on a different domain than the
/// rest of the email flow (e.g. Synvya deployments host the reset form on
/// `account.synvya.com` while verification stays on `auth.synvya.com`).
fn password_reset_base_url(default: &str) -> String {
    env::var("PASSWORD_RESET_BASE_URL").unwrap_or_else(|_| default.to_string())
}

// ---------------------------------------------------------------------------
// Shared email templates (used by SendGrid, SES, and any future providers)
// ---------------------------------------------------------------------------

/// Shared layout for single-call-to-action transactional emails (verification,
/// password reset, claim). Keeps the same wordmark / button / footer treatment
/// as the team invitation card, minus the card itself — there's no subject
/// entity to present in these flows, so stylising further risks looking like
/// phishing on what are already high-trust emails.
fn basic_email_html(
    heading: &str,
    intro: &str,
    cta_label: &str,
    cta_url: &str,
    footer_note: &str,
) -> String {
    let heading_esc = html_escape(heading);
    let intro_esc = html_escape(intro);
    let cta_label_esc = html_escape(cta_label);
    let url_esc = html_escape(cta_url);
    let footer_esc = html_escape(footer_note);

    format!(
        r#"<!doctype html>
<html>
<body style="margin:0; padding:0; background:#f5f5f5; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:#111;">
  <div style="max-width:520px; margin:0 auto; padding:32px 20px;">
    <div style="text-align:center; margin-bottom:24px;">
      <span style="color:#00B488; font-size:20px; font-weight:600; letter-spacing:0.2px;">Synvya</span>
    </div>
    <h2 style="text-align:center; margin:0 0 16px; font-size:20px; font-weight:600;">{heading_esc}</h2>
    <p style="text-align:center; color:#444; font-size:15px; line-height:1.5; margin:0 12px 28px;">{intro_esc}</p>
    <div style="margin:0 0 28px; text-align:center;">
      <a href="{url_esc}" style="display:inline-block; background:#00B488; color:#fff; padding:14px 36px; text-decoration:none; border-radius:8px; font-weight:600; font-size:15px;">{cta_label_esc}</a>
    </div>
    <p style="color:#666; font-size:13px; text-align:center; line-height:1.5; margin:0 8px;">
      Or copy and paste this link into your browser:<br>
      <a href="{url_esc}" style="color:#00B488; word-break:break-all;">{url_esc}</a>
    </p>
    <p style="color:#999; font-size:12px; text-align:center; margin-top:28px;">{footer_esc}</p>
  </div>
</body>
</html>
"#
    )
}

fn verification_email_html(verification_url: &str) -> String {
    basic_email_html(
        "Verify your Synvya email",
        "Thanks for signing up! Confirm your email address to finish creating your account.",
        "Verify Email Address",
        verification_url,
        "If you didn't sign up for Synvya, you can safely ignore this email.",
    )
}

fn verification_email_text(verification_url: &str) -> String {
    format!(
        "Thanks for signing up! Please verify your email address by clicking this link:\n\n{}\n\nIf you didn't sign up for Synvya, you can safely ignore this email.",
        verification_url
    )
}

fn password_reset_html(reset_url: &str) -> String {
    basic_email_html(
        "Reset your Synvya password",
        "We received a request to reset your password. Click the button below to set a new one.",
        "Reset Password",
        reset_url,
        "This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.",
    )
}

fn password_reset_text(reset_url: &str) -> String {
    format!(
        "We received a request to reset your password. Click this link to set a new password:\n\n{}\n\nThis link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.",
        reset_url
    )
}

fn claim_email_html(
    claim_url: &str,
    recipient_email: &str,
    account_display_name: Option<&str>,
    account_picture: Option<&str>,
) -> String {
    // Without a display name or picture there's nothing to show in a card —
    // fall back to the shared plain layout.
    if account_display_name.is_none() && account_picture.is_none() {
        return basic_email_html(
            "Your Synvya account is ready",
            "Your Synvya account is ready. Click the button below to claim it and set up your login.",
            "Claim Your Account",
            claim_url,
            "This link will expire in 7 days. If you didn't request this, you can safely ignore this email.",
        );
    }

    let name_esc = html_escape(account_display_name.unwrap_or(""));
    let recipient_esc = html_escape(recipient_email);
    let url_esc = html_escape(claim_url);

    let avatar_html = account_picture
        .and_then(safe_http_url)
        .map(|url| {
            format!(
                r#"<img src="{url}" alt="" width="72" height="72" style="width:72px; height:72px; border-radius:50%; object-fit:cover; display:block; margin:0 auto 16px;" />"#
            )
        })
        .unwrap_or_default();

    let name_html = if name_esc.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div style="font-size:18px; font-weight:600; margin-bottom:12px;">{name_esc}</div>"#
        )
    };

    format!(
        r#"<!doctype html>
<html>
<body style="margin:0; padding:0; background:#f5f5f5; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:#111;">
  <div style="max-width:520px; margin:0 auto; padding:32px 20px;">
    <div style="text-align:center; margin-bottom:24px;">
      <span style="color:#00B488; font-size:20px; font-weight:600; letter-spacing:0.2px;">Synvya</span>
    </div>
    <h2 style="text-align:center; margin:0 0 20px; font-size:20px; font-weight:600;">Your Synvya account is ready</h2>
    <div style="background:#fff; border-radius:12px; padding:28px 24px; text-align:center; border:1px solid #ececec;">
      {avatar_html}{name_html}<div style="color:#444; font-size:14px;">Claim your login for <strong>{recipient_esc}</strong>.</div>
    </div>
    <div style="margin:28px 0; text-align:center;">
      <a href="{url_esc}" style="display:inline-block; background:#00B488; color:#fff; padding:14px 36px; text-decoration:none; border-radius:8px; font-weight:600; font-size:15px;">Claim Your Account</a>
    </div>
    <p style="color:#666; font-size:13px; text-align:center; line-height:1.5; margin:0 8px;">
      Or copy and paste this link into your browser:<br>
      <a href="{url_esc}" style="color:#00B488; word-break:break-all;">{url_esc}</a>
    </p>
    <p style="color:#999; font-size:12px; text-align:center; margin-top:28px;">
      This link will expire in 7 days. If you didn't request this, you can safely ignore this email.
    </p>
  </div>
</body>
</html>
"#
    )
}

fn claim_email_text(claim_url: &str) -> String {
    format!(
        "Your Synvya account is ready. Click this link to claim it:\n\n{}\n\nThis link will expire in 7 days. If you didn't request this, you can safely ignore this email.",
        claim_url
    )
}

/// Minimal HTML-attribute/text escape for values interpolated into the template.
/// Handles the five chars that matter in body text and double-quoted attributes.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Keep only http/https URLs; reject anything else to avoid `javascript:` etc.
/// Returned string is already HTML-attribute-safe.
fn safe_http_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        Some(html_escape(trimmed))
    } else {
        None
    }
}

fn title_case_role(role: &str) -> String {
    let mut chars = role.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn team_invite_html(
    team_display_name: &str,
    team_picture: Option<&str>,
    inviter_label: &str,
    recipient_email: &str,
    role: &str,
    expires_at: DateTime<Utc>,
    invite_url: &str,
) -> String {
    let team_name_esc = html_escape(team_display_name);
    let inviter_esc = html_escape(inviter_label);
    let recipient_esc = html_escape(recipient_email);
    let role_esc = html_escape(&title_case_role(role));
    let url_esc = html_escape(invite_url);
    // "Apr 28, 2026" — date only, TZ-ambiguous time would confuse recipients.
    let expires_fmt = expires_at.format("%b %-d, %Y").to_string();

    let avatar_html = team_picture
        .and_then(safe_http_url)
        .map(|url| {
            format!(
                r#"<img src="{url}" alt="" width="72" height="72" style="width:72px; height:72px; border-radius:50%; object-fit:cover; display:block; margin:0 auto 16px;" />"#
            )
        })
        .unwrap_or_default();

    // Shared inline styles for the labeled-field rows. Inlined per row because
    // many email clients strip <style> blocks. See ui-shell-pattern.md §13 for
    // the layout convention.
    let label_td =
        "padding:6px 12px 6px 0; color:#888; font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap; vertical-align:top; width:72px;";
    let value_td =
        "padding:6px 0; color:#111; font-size:14px; word-break:break-all; vertical-align:top;";

    format!(
        r#"<!doctype html>
<html>
<body style="margin:0; padding:0; background:#f5f5f5; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:#111;">
  <div style="max-width:520px; margin:0 auto; padding:32px 20px;">
    <div style="text-align:center; margin-bottom:24px;">
      <span style="color:#00B488; font-size:20px; font-weight:600; letter-spacing:0.2px;">Synvya</span>
    </div>
    <h2 style="text-align:center; margin:0 0 20px; font-size:20px; font-weight:600;">Team Invitation</h2>
    <div style="background:#fff; border-radius:12px; padding:28px 24px; border:1px solid #ececec;">
      <div style="text-align:center;">
        {avatar_html}<div style="font-size:18px; font-weight:600; margin-bottom:20px;">{team_name_esc}</div>
      </div>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="width:100%; border-collapse:collapse;">
        <tr>
          <td style="{label_td}">From</td>
          <td style="{value_td}">{inviter_esc}</td>
        </tr>
        <tr>
          <td style="{label_td}">To</td>
          <td style="{value_td}">{recipient_esc}</td>
        </tr>
        <tr>
          <td style="{label_td}">Role</td>
          <td style="{value_td}">{role_esc}</td>
        </tr>
        <tr>
          <td style="{label_td}">Expires</td>
          <td style="{value_td}">{expires_fmt}</td>
        </tr>
      </table>
    </div>
    <div style="margin:28px 0; text-align:center;">
      <a href="{url_esc}" style="display:inline-block; background:#00B488; color:#fff; padding:14px 36px; text-decoration:none; border-radius:8px; font-weight:600; font-size:15px;">Accept Invitation</a>
    </div>
    <p style="color:#666; font-size:13px; text-align:center; line-height:1.5; margin:0 8px;">
      Or copy and paste this link into your browser:<br>
      <a href="{url_esc}" style="color:#00B488; word-break:break-all;">{url_esc}</a>
    </p>
    <p style="color:#999; font-size:12px; text-align:center; margin-top:28px;">
      This invitation expires in 7 days. If you didn't expect this email, you can safely ignore it.
    </p>
  </div>
</body>
</html>
"#
    )
}

fn team_invite_text(
    team_display_name: &str,
    inviter_label: &str,
    recipient_email: &str,
    role: &str,
    expires_at: DateTime<Utc>,
    invite_url: &str,
) -> String {
    let role_tc = title_case_role(role);
    let expires_fmt = expires_at.format("%b %-d, %Y").to_string();
    format!(
        "Team Invitation — {team_display_name}\n\n\
         From:    {inviter_label}\n\
         To:      {recipient_email}\n\
         Role:    {role_tc}\n\
         Expires: {expires_fmt}\n\n\
         Accept the invitation:\n{invite_url}\n\n\
         This invitation expires in 7 days. If you didn't expect this email, you can safely ignore it.\n",
    )
}

// ---------------------------------------------------------------------------
// Development email sender
// ---------------------------------------------------------------------------

/// Development email sender - logs URLs to console and captures emails for testing
pub struct DevEmailSender {
    base_url: String,
    password_reset_base_url: String,
    captured: Arc<Mutex<Vec<CapturedEmail>>>,
}

impl DevEmailSender {
    pub fn new() -> Self {
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());
        let password_reset_base_url = password_reset_base_url(&base_url);

        tracing::info!("===========================================");
        tracing::info!("  EMAIL SERVICE: Development Mode");
        tracing::info!("  Emails will be logged to console");
        tracing::info!("  Base URL: {}", base_url);
        tracing::info!("  Password reset base URL: {}", password_reset_base_url);
        tracing::info!("===========================================");

        Self {
            base_url,
            password_reset_base_url,
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get a clone of the captured emails storage for sharing with tests
    pub fn captured_emails(&self) -> Arc<Mutex<Vec<CapturedEmail>>> {
        self.captured.clone()
    }
}

impl Default for DevEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailSender for DevEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  VERIFICATION EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Subject: Verify your Synvya email address");
        tracing::info!("");
        tracing::info!("  Click to verify:");
        tracing::info!("  {}", verification_url);
        tracing::info!("==================================================");
        tracing::info!("");

        // Also print to stderr so it's visible even with log filtering
        eprintln!(
            "\n\x1b[32m[DEV EMAIL]\x1b[0m Verification link for {}: \x1b[4m{}\x1b[0m\n",
            to_email, verification_url
        );

        // Capture for testing
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: "Verify your Synvya email address".to_string(),
                verification_url: Some(verification_url),
                reset_url: None,
            });
        }

        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
        base_url_override: Option<&str>,
    ) -> Result<(), String> {
        let base = base_url_override
            .map(|s| s.trim_end_matches('/'))
            .unwrap_or(self.password_reset_base_url.as_str());
        let reset_url = format!("{}/reset-password?token={}", base, reset_token);

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  PASSWORD RESET EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Subject: Reset your Synvya password");
        tracing::info!("");
        tracing::info!("  Click to reset password:");
        tracing::info!("  {}", reset_url);
        tracing::info!("==================================================");
        tracing::info!("");

        // Also print to stderr so it's visible even with log filtering
        eprintln!(
            "\n\x1b[33m[DEV EMAIL]\x1b[0m Password reset link for {}: \x1b[4m{}\x1b[0m\n",
            to_email, reset_url
        );

        // Capture for testing
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: "Reset your Synvya password".to_string(),
                verification_url: None,
                reset_url: Some(reset_url),
            });
        }

        Ok(())
    }

    async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
        account_display_name: Option<&str>,
        account_picture: Option<&str>,
    ) -> Result<(), String> {
        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  SYNVYA CLAIM EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Subject: Your Synvya account is ready to claim");
        tracing::info!("  Display name: {:?}", account_display_name);
        tracing::info!("  Picture: {:?}", account_picture);
        tracing::info!("");
        tracing::info!("  Claim link:");
        tracing::info!("  {}", claim_url);
        tracing::info!("==================================================");
        tracing::info!("");

        eprintln!(
            "\n\x1b[36m[DEV EMAIL]\x1b[0m Synvya claim link for {}: \x1b[4m{}\x1b[0m\n",
            to_email, claim_url
        );

        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: "Your Synvya account is ready to claim".to_string(),
                verification_url: Some(claim_url.to_string()),
                reset_url: None,
            });
        }

        Ok(())
    }

    async fn send_team_invite_email(
        &self,
        to_email: &str,
        team_display_name: &str,
        team_picture: Option<&str>,
        inviter_label: &str,
        role: &str,
        expires_at: DateTime<Utc>,
        invite_url: &str,
    ) -> Result<(), String> {
        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  TEAM INVITATION EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Team: {} (as {})", team_display_name, role);
        tracing::info!("  Invited by: {}", inviter_label);
        tracing::info!("  Picture: {:?}", team_picture);
        tracing::info!("  Expires: {}", expires_at);
        tracing::info!("");
        tracing::info!("  Accept link:");
        tracing::info!("  {}", invite_url);
        tracing::info!("==================================================");
        tracing::info!("");

        eprintln!(
            "\n\x1b[35m[DEV EMAIL]\x1b[0m Team invite for {} to join {}: \x1b[4m{}\x1b[0m\n",
            to_email, team_display_name, invite_url
        );

        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: format!(
                    "You've been invited to join {} on Synvya",
                    team_display_name
                ),
                verification_url: Some(invite_url.to_string()),
                reset_url: None,
            });
        }

        Ok(())
    }

    fn get_captured_emails(&self) -> Vec<CapturedEmail> {
        self.captured
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn clear_captured_emails(&self) {
        if let Ok(mut captured) = self.captured.lock() {
            captured.clear();
        }
    }
}

// ---------------------------------------------------------------------------
// SendGrid email sender
// ---------------------------------------------------------------------------

// SendGrid API types
#[derive(Debug, Serialize)]
struct SendGridEmail {
    personalizations: Vec<Personalization>,
    from: EmailAddress,
    subject: String,
    content: Vec<Content>,
    tracking_settings: TrackingSettings,
}

#[derive(Debug, Serialize)]
struct TrackingSettings {
    click_tracking: ClickTracking,
    open_tracking: OpenTracking,
}

#[derive(Debug, Serialize)]
struct ClickTracking {
    enable: bool,
}

#[derive(Debug, Serialize)]
struct OpenTracking {
    enable: bool,
}

#[derive(Debug, Serialize)]
struct Personalization {
    to: Vec<EmailAddress>,
}

#[derive(Debug, Serialize)]
struct EmailAddress {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

/// Production email sender using SendGrid API
pub struct SendGridEmailSender {
    api_key: String,
    from_email: String,
    from_name: String,
    base_url: String,
    password_reset_base_url: String,
}

impl SendGridEmailSender {
    pub fn new(api_key: String) -> Self {
        let from_email =
            env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@divine.video".to_string());
        let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Synvya".to_string());
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());
        let password_reset_base_url = password_reset_base_url(&base_url);

        tracing::info!(
            "Email service initialized with SendGrid (reset base URL: {})",
            password_reset_base_url
        );

        Self {
            api_key,
            from_email,
            from_name,
            base_url,
            password_reset_base_url,
        }
    }

    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_content: &str,
        text_content: &str,
    ) -> Result<(), String> {
        // Check if emails are disabled (useful for load testing)
        if env::var("DISABLE_EMAILS").is_ok() {
            tracing::info!(
                "Emails disabled via DISABLE_EMAILS env var, skipping email to {}",
                to_email
            );
            return Ok(());
        }

        let email = SendGridEmail {
            personalizations: vec![Personalization {
                to: vec![EmailAddress {
                    email: to_email.to_string(),
                    name: None,
                }],
            }],
            from: EmailAddress {
                email: self.from_email.clone(),
                name: Some(self.from_name.clone()),
            },
            subject: subject.to_string(),
            content: vec![
                Content {
                    content_type: "text/plain".to_string(),
                    value: text_content.to_string(),
                },
                Content {
                    content_type: "text/html".to_string(),
                    value: html_content.to_string(),
                },
            ],
            // Disable tracking for security-sensitive emails (verification, password reset)
            // to prevent tokens from passing through SendGrid's redirect servers
            tracking_settings: TrackingSettings {
                click_tracking: ClickTracking { enable: false },
                open_tracking: OpenTracking { enable: false },
            },
        };

        let client = reqwest::Client::new();
        let response = client
            .post("https://api.sendgrid.com/v3/mail/send")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&email)
            .send()
            .await
            .map_err(|e| format!("Failed to send email: {}", e))?;

        if response.status().is_success() {
            tracing::info!("Email sent successfully to {}", to_email);
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Could not read response body".to_string());
            tracing::error!("SendGrid API error: {} - {}", status, body);
            Err(format!("Failed to send email: {} - {}", status, body))
        }
    }
}

#[async_trait]
impl EmailSender for SendGridEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );
        let subject = "Verify your Synvya email address";
        let html = verification_email_html(&verification_url);
        let text = verification_email_text(&verification_url);

        self.send_email(to_email, subject, &html, &text).await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
        base_url_override: Option<&str>,
    ) -> Result<(), String> {
        let base = base_url_override
            .map(|s| s.trim_end_matches('/'))
            .unwrap_or(self.password_reset_base_url.as_str());
        let reset_url = format!("{}/reset-password?token={}", base, reset_token);
        let subject = "Reset your Synvya password";
        let html = password_reset_html(&reset_url);
        let text = password_reset_text(&reset_url);

        self.send_email(to_email, subject, &html, &text).await
    }

    async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
        account_display_name: Option<&str>,
        account_picture: Option<&str>,
    ) -> Result<(), String> {
        let subject = "Your Synvya account is ready to claim";
        let html = claim_email_html(claim_url, to_email, account_display_name, account_picture);
        let text = claim_email_text(claim_url);

        self.send_email(to_email, subject, &html, &text).await
    }

    async fn send_team_invite_email(
        &self,
        to_email: &str,
        team_display_name: &str,
        team_picture: Option<&str>,
        inviter_label: &str,
        role: &str,
        expires_at: DateTime<Utc>,
        invite_url: &str,
    ) -> Result<(), String> {
        let subject = format!(
            "You've been invited to join {} on Synvya",
            team_display_name
        );
        let html = team_invite_html(
            team_display_name,
            team_picture,
            inviter_label,
            to_email,
            role,
            expires_at,
            invite_url,
        );
        let text = team_invite_text(
            team_display_name,
            inviter_label,
            to_email,
            role,
            expires_at,
            invite_url,
        );

        self.send_email(to_email, &subject, &html, &text).await
    }
}

// ---------------------------------------------------------------------------
// AWS SES email sender (behind `aws` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "aws")]
pub struct SesEmailSender {
    client: aws_sdk_sesv2::Client,
    from_email: String,
    from_name: String,
    base_url: String,
    password_reset_base_url: String,
}

#[cfg(feature = "aws")]
impl SesEmailSender {
    pub async fn new() -> Result<Self, String> {
        let region = env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;

        let client = aws_sdk_sesv2::Client::new(&config);

        let from_email =
            env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@divine.video".to_string());
        let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Synvya".to_string());
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());
        let password_reset_base_url = password_reset_base_url(&base_url);

        tracing::info!(
            "AWS SES email sender initialized (region: {}, from: {}, reset base URL: {})",
            region,
            from_email,
            password_reset_base_url
        );

        Ok(Self {
            client,
            from_email,
            from_name,
            base_url,
            password_reset_base_url,
        })
    }

    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        html: &str,
        text: &str,
    ) -> Result<(), String> {
        // Check if emails are disabled (useful for load testing)
        if env::var("DISABLE_EMAILS").is_ok() {
            tracing::info!(
                "Emails disabled via DISABLE_EMAILS env var, skipping email to {}",
                to
            );
            return Ok(());
        }

        use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

        let from = format!("{} <{}>", self.from_name, self.from_email);

        self.client
            .send_email()
            .from_email_address(&from)
            .destination(Destination::builder().to_addresses(to).build())
            .content(
                EmailContent::builder()
                    .simple(
                        Message::builder()
                            .subject(
                                Content::builder()
                                    .data(subject)
                                    .charset("UTF-8")
                                    .build()
                                    .map_err(|e| format!("SES subject build error: {}", e))?,
                            )
                            .body(
                                Body::builder()
                                    .html(
                                        Content::builder()
                                            .data(html)
                                            .charset("UTF-8")
                                            .build()
                                            .map_err(|e| {
                                                format!("SES html content build error: {}", e)
                                            })?,
                                    )
                                    .text(
                                        Content::builder()
                                            .data(text)
                                            .charset("UTF-8")
                                            .build()
                                            .map_err(|e| {
                                                format!("SES text content build error: {}", e)
                                            })?,
                                    )
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await
            .map_err(|e| format!("SES send failed: {:?}", e))?;

        tracing::debug!("Email sent to {} via SES", to);
        Ok(())
    }
}

#[cfg(feature = "aws")]
#[async_trait]
impl EmailSender for SesEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );
        let subject = "Verify your Synvya email address";
        let html = verification_email_html(&verification_url);
        let text = verification_email_text(&verification_url);

        self.send_email(to_email, subject, &html, &text).await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
        base_url_override: Option<&str>,
    ) -> Result<(), String> {
        let base = base_url_override
            .map(|s| s.trim_end_matches('/'))
            .unwrap_or(self.password_reset_base_url.as_str());
        let reset_url = format!("{}/reset-password?token={}", base, reset_token);
        let subject = "Reset your Synvya password";
        let html = password_reset_html(&reset_url);
        let text = password_reset_text(&reset_url);

        self.send_email(to_email, subject, &html, &text).await
    }

    async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
        account_display_name: Option<&str>,
        account_picture: Option<&str>,
    ) -> Result<(), String> {
        let subject = "Your Synvya account is ready to claim";
        let html = claim_email_html(claim_url, to_email, account_display_name, account_picture);
        let text = claim_email_text(claim_url);

        self.send_email(to_email, subject, &html, &text).await
    }

    async fn send_team_invite_email(
        &self,
        to_email: &str,
        team_display_name: &str,
        team_picture: Option<&str>,
        inviter_label: &str,
        role: &str,
        expires_at: DateTime<Utc>,
        invite_url: &str,
    ) -> Result<(), String> {
        let subject = format!(
            "You've been invited to join {} on Synvya",
            team_display_name
        );
        let html = team_invite_html(
            team_display_name,
            team_picture,
            inviter_label,
            to_email,
            role,
            expires_at,
            invite_url,
        );
        let text = team_invite_text(
            team_display_name,
            inviter_label,
            to_email,
            role,
            expires_at,
            invite_url,
        );

        self.send_email(to_email, &subject, &html, &text).await
    }
}

// ---------------------------------------------------------------------------
// Provider selection
// ---------------------------------------------------------------------------

/// Create the appropriate email sender based on environment configuration.
///
/// Selection logic:
/// - `EMAIL_PROVIDER=sendgrid` → SendGrid (requires `SENDGRID_API_KEY`)
/// - `EMAIL_PROVIDER=ses` → AWS SES (requires `aws` feature)
/// - `EMAIL_PROVIDER=dev` → Development logger
/// - No `EMAIL_PROVIDER` set → backward compat: use SendGrid if `SENDGRID_API_KEY` is present, else dev
pub async fn create_email_sender() -> Arc<dyn EmailSender> {
    let provider = env::var("EMAIL_PROVIDER").unwrap_or_else(|_| {
        // Backward compatibility: SENDGRID_API_KEY presence → "sendgrid"
        if env::var("SENDGRID_API_KEY")
            .map(|k| !k.is_empty())
            .unwrap_or(false)
        {
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
            let sender = SesEmailSender::new()
                .await
                .expect("Failed to initialize AWS SES email sender");
            Arc::new(sender)
        }
        #[cfg(not(feature = "aws"))]
        "ses" => {
            panic!("EMAIL_PROVIDER=ses requires the 'aws' feature to be enabled at compile time");
        }
        _ => {
            tracing::warn!("Using development email sender (emails logged to console)");
            Arc::new(DevEmailSender::new())
        }
    }
}

/// Legacy EmailService for backward compatibility during migration
/// TODO: Remove once all usages are migrated to the trait
pub struct EmailService {
    inner: Arc<dyn EmailSender>,
}

impl EmailService {
    pub async fn new() -> Result<Self, String> {
        Ok(Self {
            inner: create_email_sender().await,
        })
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        self.inner
            .send_verification_email(to_email, verification_token)
            .await
    }

    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
        base_url_override: Option<&str>,
    ) -> Result<(), String> {
        self.inner
            .send_password_reset_email(to_email, reset_token, base_url_override)
            .await
    }

    pub async fn send_claim_email(
        &self,
        to_email: &str,
        claim_url: &str,
        account_display_name: Option<&str>,
        account_picture: Option<&str>,
    ) -> Result<(), String> {
        self.inner
            .send_claim_email(to_email, claim_url, account_display_name, account_picture)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_team_invite_email(
        &self,
        to_email: &str,
        team_display_name: &str,
        team_picture: Option<&str>,
        inviter_label: &str,
        role: &str,
        expires_at: DateTime<Utc>,
        invite_url: &str,
    ) -> Result<(), String> {
        self.inner
            .send_team_invite_email(
                to_email,
                team_display_name,
                team_picture,
                inviter_label,
                role,
                expires_at,
                invite_url,
            )
            .await
    }
}
