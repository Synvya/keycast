# Vine Import Guide for Keycast

This guide explains how to use the Keycast Admin API to bulk import Vine accounts to Nostr.

## Overview

The import flow:
1. Get an admin token (one-time setup)
2. For each Vine user: create a preloaded account
3. Sign Nostr events (profile, videos) using the user's token
4. Publish events to your relay
5. Generate claim links for users to recover their accounts later

## Authentication

### Getting an Admin Token

**Prerequisites**: Your Nostr pubkey must be in the `ALLOWED_PUBKEYS` environment variable.

**Option 1: Web UI**
1. Go to https://login.divine.video/admin
2. Click "NIP-07 Admin Login" and sign with your browser extension
3. Click "Generate Admin Token"
4. Copy the token (valid for 30 days)

**Option 2: API** (if already logged in)
```bash
GET /api/admin/token
Authorization: Bearer <session_cookie_or_ucan>

# Response:
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9...",
  "expires_at": "2025-02-18T00:00:00Z"
}
```

## API Endpoints

### 1. Create Preloaded User

Creates a Nostr account for a Vine user without email/password.

```bash
POST /api/admin/preload-user
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json

{
  "vine_id": "12345",           # Required: Vine user ID (must be unique)
  "username": "alice",          # Required: Username (must be unique)
  "display_name": "Alice Smith" # Optional: Display name
}
```

**Response:**
```json
{
  "pubkey": "abc123def456...",  // 64-char hex Nostr public key
  "token": "eyJ0eXAi..."        // UCAN token for signing (valid 30 days)
}
```

**Errors:**
- `409 Conflict`: User with this vine_id or username already exists
- `403 Forbidden`: Caller is not an admin

### 2. Sign Events (HTTP RPC)

Sign Nostr events on behalf of the preloaded user.

```bash
POST /api/nostr
Authorization: Bearer <USER_TOKEN>  # Token from preload-user response
Content-Type: application/json

{
  "method": "sign_event",
  "params": [{
    "kind": 0,
    "content": "{\"name\":\"Alice\",\"about\":\"Vine creator\"}",
    "created_at": 1705000000,
    "tags": []
  }]
}
```

**Response:**
```json
{
  "result": {
    "id": "event_id_hex",
    "pubkey": "user_pubkey_hex",
    "created_at": 1705000000,
    "kind": 0,
    "tags": [],
    "content": "{\"name\":\"Alice\",\"about\":\"Vine creator\"}",
    "sig": "signature_hex"
  }
}
```

**Available RPC Methods:**
- `sign_event(unsigned_event)` - Sign any Nostr event
- `get_public_key()` - Get user's hex pubkey
- `nip44_encrypt(recipient_pubkey, plaintext)` - Encrypt with NIP-44
- `nip44_decrypt(sender_pubkey, ciphertext)` - Decrypt with NIP-44

### 3. Generate Claim Link

Create a recovery link for the user to set email/password later.

```bash
POST /api/admin/claim-tokens
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/json

{
  "vine_id": "12345"
}
```

**Response:**
```json
{
  "claim_url": "https://login.divine.video/api/claim?token=abc123...",
  "expires_at": "2025-02-18T00:00:00Z"
}
```

**Errors:**
- `404 Not Found`: No user with this vine_id
- `409 Conflict`: User has already claimed their account

## Event Types

### Profile Event (Kind 0)

```json
{
  "kind": 0,
  "content": "{\"name\":\"Display Name\",\"about\":\"Bio text\",\"picture\":\"https://...\",\"nip05\":\"user@domain.com\"}",
  "created_at": 1705000000,
  "tags": []
}
```

### Text Note (Kind 1)

```json
{
  "kind": 1,
  "content": "Hello world!",
  "created_at": 1705000000,
  "tags": []
}
```

### Video Event (Kind 34236 - NIP-71 Short Video)

Vine videos are 6-second square loops - use kind 34236 (short video) not 34235 (normal video).

```json
{
  "kind": 34236,
  "content": "Video description",
  "created_at": 1705000000,
  "tags": [
    ["d", "unique-video-id"],
    ["title", "My Vine Video"],
    ["url", "https://cdn.example.com/video.mp4"],
    ["m", "video/mp4"],
    ["thumb", "https://cdn.example.com/thumb.jpg"],
    ["duration", "6"]
  ]
}
```

## Example Migration Script Flow

```python
import requests

KEYCAST_URL = "https://login.divine.video"
ADMIN_TOKEN = "your_admin_token"
RELAY_URL = "wss://relay.divine.video"

def import_vine_user(vine_user):
    # 1. Create preloaded account
    resp = requests.post(
        f"{KEYCAST_URL}/api/admin/preload-user",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={
            "vine_id": vine_user["id"],
            "username": vine_user["username"],
            "display_name": vine_user.get("displayName")
        }
    )
    resp.raise_for_status()
    account = resp.json()

    user_pubkey = account["pubkey"]
    user_token = account["token"]

    # 2. Sign profile event
    profile_event = {
        "kind": 0,
        "content": json.dumps({
            "name": vine_user.get("displayName", vine_user["username"]),
            "about": vine_user.get("bio", ""),
            "picture": vine_user.get("avatarUrl", "")
        }),
        "created_at": int(time.time()),
        "tags": []
    }

    signed_profile = sign_event(user_token, profile_event)
    publish_to_relay(RELAY_URL, signed_profile)

    # 3. Sign video events
    for video in vine_user.get("videos", []):
        video_event = {
            "kind": 34235,
            "content": video.get("description", ""),
            "created_at": video.get("created_at", int(time.time())),
            "tags": [
                ["d", video["id"]],
                ["title", video.get("title", "")],
                ["url", video["videoUrl"]],
                ["m", "video/mp4"],
                ["thumb", video.get("thumbnailUrl", "")],
                ["duration", str(video.get("duration", 6))]
            ]
        }
        signed_video = sign_event(user_token, video_event)
        publish_to_relay(RELAY_URL, signed_video)

    # 4. Generate claim link
    resp = requests.post(
        f"{KEYCAST_URL}/api/admin/claim-tokens",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"vine_id": vine_user["id"]}
    )
    claim_data = resp.json()

    return {
        "pubkey": user_pubkey,
        "claim_url": claim_data["claim_url"]
    }

def sign_event(user_token, unsigned_event):
    resp = requests.post(
        f"{KEYCAST_URL}/api/nostr",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"method": "sign_event", "params": [unsigned_event]}
    )
    resp.raise_for_status()
    return resp.json()["result"]
```

## Rate Limits & Best Practices

1. **Batch Processing**: Process users in parallel with a concurrency limit (e.g., 10-50 concurrent)
2. **Token Caching**: User tokens are valid for 30 days - cache them if re-running imports
3. **Idempotency**: The API returns 409 Conflict for duplicate vine_id/username - safe to retry
4. **Error Handling**: Log failures and continue - don't let one user fail the whole batch
5. **Relay Publishing**: Use websocket connection pooling for publishing to relays

## Database Schema Reference

Relevant tables:
- `users`: pubkey, email (nullable), username, display_name, vine_id, email_verified
- `personal_keys`: user_pubkey, encrypted_secret_key (AES-256-GCM)
- `account_claim_tokens`: token, user_pubkey, expires_at, used_at

## Environment Variables

For local development:
```bash
DATABASE_URL=postgres://user:pass@localhost/keycast
MASTER_KEY_PATH=./master.key
SERVER_NSEC=<hex_or_nsec_server_key>
ALLOWED_PUBKEYS=<your_hex_pubkey>
BUNKER_RELAYS=wss://relay.divine.video
```
