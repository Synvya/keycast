# Email Verification Polling for OAuth Flow

## Problem Statement

The current OAuth registration flow with email verification (commit 60bc04f) has a critical limitation: **it only works if the user verifies their email on the same device** where they started the registration.

### Current Flow (Broken for Multi-Device)

1. User starts OAuth flow in mobile app (Device A)
2. ASWebAuthenticationSession opens keycast login page
3. User registers → Server returns `{verification_required: true}`
4. OAuth page shows "Check your email"
5. User opens email on laptop (Device B) and clicks verification link
6. Server verifies email, returns `{redirect_to: "callback?code=xxx"}`
7. **Device B's browser redirects** → but Device A's OAuth page is still stuck on "Check your email"

The OAuth page on Device A has no way to know that verification completed on Device B.

## Solution: Server-Side Polling with Redis

The OAuth page should poll for verification completion. When email is verified (on any device), the poll returns the authorization code.

### Why Redis (Not In-Memory Cache)

The current `POLLING_CACHE` is an in-memory `DashMap`. This won't work because:
- Cloud Run runs multiple instances
- The instance handling registration may differ from the instance handling email verification
- In-memory caches are not shared across instances

**Redis is already used by keycast** for other purposes and provides shared state across all Cloud Run instances.

## Implementation Requirements

### 1. Redis Cache for Polling

Replace the in-memory `POLLING_CACHE` with Redis-based storage:

```rust
// Key format: oauth_poll:{state}
// Value: authorization code
// TTL: 5-10 minutes (matches current POLLING_TTL)
```

### 2. OAuth Page JavaScript Changes

**File: `api/src/api/http/oauth.rs`** (inline JavaScript around line 1611)

Add polling to `showVerificationNotice()`:

```javascript
function showVerificationNotice(email) {
    // Hide forms and show verification notice (existing code)
    document.getElementById('login_view').classList.remove('active');
    document.getElementById('register_view').classList.remove('active');
    hideError();

    const notice = document.getElementById('verification_notice');
    const emailSpan = document.getElementById('verification_email');
    if (emailSpan) emailSpan.textContent = email;
    notice.style.display = 'block';

    // NEW: Start polling for verification completion
    startVerificationPolling();
}

function startVerificationPolling() {
    const urlParams = new URLSearchParams(window.location.search);
    const state = urlParams.get('state');

    if (!state) {
        console.log('No state parameter, polling disabled');
        return;
    }

    console.log('Starting verification polling with state:', state);

    const pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/oauth/poll?state=${encodeURIComponent(state)}`);

            if (response.status === 200) {
                // Verification complete, code is ready
                clearInterval(pollInterval);
                const data = await response.json();
                const code = data.code;

                // Redirect to callback with code
                let redirectUrl = `${redirectUri}?code=${encodeURIComponent(code)}`;
                if (state) {
                    redirectUrl += `&state=${encodeURIComponent(state)}`;
                }
                window.location.href = redirectUrl;
            } else if (response.status === 202) {
                // Still pending, continue polling
                console.log('Verification still pending...');
            } else {
                // Error or expired
                console.error('Polling error:', response.status);
                clearInterval(pollInterval);
            }
        } catch (err) {
            console.error('Polling failed:', err);
        }
    }, 2000); // Poll every 2 seconds

    // Stop polling after 30 minutes (email verification link expires in 24h, but user won't wait that long)
    setTimeout(() => {
        clearInterval(pollInterval);
        console.log('Polling timed out');
    }, 30 * 60 * 1000);
}
```

### 3. Verify Email Endpoint Changes

**File: `api/src/api/http/auth.rs`** - In the OAuth flow section of `verify_email()`

After generating the new authorization code, insert it into Redis:

```rust
// After: let new_code: String = ... (around where POLLING_CACHE would be used)

// If state was provided, store code in Redis for polling
if let Some(ref state) = oauth_data.state {
    // Use Redis to store: key = "oauth_poll:{state}", value = new_code, TTL = 10 minutes
    redis_client
        .set_ex(
            format!("oauth_poll:{}", state),
            &new_code,
            600, // 10 minutes
        )
        .await?;

    tracing::info!(
        "Stored OAuth code in Redis for polling: state={}",
        state
    );
}
```

### 4. Update Poll Endpoint to Use Redis

**File: `api/src/api/http/oauth.rs`** - `poll()` function

```rust
pub async fn poll(
    State(auth_state): State<AuthState>,
    Query(req): Query<PollRequest>,
) -> Result<Response, OAuthError> {
    let redis = &auth_state.state.redis;
    let key = format!("oauth_poll:{}", req.state);

    // Try to get code from Redis
    match redis.get::<Option<String>>(&key).await? {
        Some(code) => {
            // Code found - delete from Redis (one-time use) and return
            redis.del(&key).await?;
            Ok((StatusCode::OK, Json(PollResponse { code })).into_response())
        }
        None => {
            // Code not ready yet
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({ "status": "pending" })),
            ).into_response())
        }
    }
}
```

## Client Requirements

Clients must include the `state` parameter in the authorization URL for polling to work:

```
GET /api/oauth/authorize?
  client_id=divine-flutter-demo&
  redirect_uri=https://login.divine.video/app/callback&
  code_challenge=xxx&
  code_challenge_method=S256&
  state=random_32_byte_base64url_string   <-- REQUIRED for polling
```

The state parameter serves dual purposes:
1. CSRF protection (standard OAuth 2.0)
2. Polling key for multi-device email verification

## Testing Checklist

- [ ] Registration with email verification (same device)
- [ ] Registration with email verification (different device) - **the critical test**
- [ ] Existing user login (should work unchanged)
- [ ] Silent re-auth with authorization_handle (should work unchanged)
- [ ] State parameter missing (should fall back to redirect-only flow)
- [ ] Poll timeout handling
- [ ] Redis connection failure handling

## Security Considerations

- State should be cryptographically random (32 bytes, base64url encoded)
- Redis keys should have TTL to prevent memory leaks
- Code should be deleted from Redis after successful retrieval (one-time use)
- Rate limiting on poll endpoint to prevent abuse
