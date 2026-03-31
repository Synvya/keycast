# Synvya — Architecture Context for Keycast

Keycast provides key custody and authentication for restaurant owners and customers in Synvya's platform. Synvya's own services (Lambda, MCP server, Event Processor) keep their own keys in AWS Secrets Manager, not in Keycast.

## Related Specs

Read these before starting work on Synvya-specific Keycast modifications:

| Document | Purpose |
|---|---|
| [`Synvya/docs` — Auth & Real-Time Event Processing](https://github.com/Synvya/docs/blob/main/architecture/auth-and-realtime.md) | System-wide architecture, Keycast's role, API contracts, deployment topology |
| [`Synvya/client` — Auth Migration](https://github.com/Synvya/client/blob/main/docs/specs/auth-migration.md) | Client migration from local keys to Keycast-backed signing and auth |
| [`Synvya/event-processor` — Event Processor](https://github.com/Synvya/event-processor/blob/main/docs/specs/event-processor.md) | 24/7 Nostr event processing, uses Keycast RPC for signing/decryption |
| [`Synvya/mcp-server` — Thin Client Migration](https://github.com/Synvya/mcp-server/blob/main/docs/specs/thin-client-migration.md) | MCP server migration to Event Processor API (does NOT use Keycast) |

## What Synvya Needs from Keycast

- **AWS KMS encryption provider** — replace GCP KMS for master key encryption (contributable upstream)
- **AWS SES email provider** — replace SendGrid/GCP for email verification (contributable upstream)
- **EC2/Docker deployment** — replace Cloud Run with Docker Compose on EC2 (Synvya-specific)
- **NIP-46 remote signing** — already built into Keycast, used by the Event Processor for 24/7 signing and by the client for user-initiated signing
- **OAuth 2.0 + email/password auth** — already built into Keycast, used by the client for login
