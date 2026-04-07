# Synvya — Architecture Context for Keycast

Keycast provides authentication, key custody, and signing/decryption RPC for restaurant owners and customers in Synvya.

It does not own Synvya's business API or discovery cache. Those live in `Synvya/server`.

## Related Specs

| Document | Purpose |
|---|---|
| [`Synvya/docs` — Auth & Real-Time Event Processing](https://github.com/Synvya/docs/blob/main/architecture/auth-and-realtime.md) | System-wide architecture and service boundaries |
| [`Synvya/docs` — Responsibility Matrix](https://github.com/Synvya/docs/blob/main/architecture/responsibility-matrix.md) | Shared ownership model for client/server/Keycast responsibilities |
| [`Synvya/server` — Server Spec](https://github.com/Synvya/server/blob/main/docs/specs/server.md) | 24/7 reservation processing, discovery sync, internal API |
| [`Synvya/client` — Auth Migration](https://github.com/Synvya/client/blob/main/docs/specs/auth-migration.md) | Client migration to Keycast-backed auth/signing |
| [`Synvya/client` — Client Nostr Boundary](https://github.com/Synvya/client/blob/main/docs/specs/nostr-boundary.md) | What stays in the client vs what moves to the server |
| [`docs/synvya/specs/keycast-boundary.md`](specs/keycast-boundary.md) | Keycast-specific ownership boundary inside Synvya |
| [`docs/synvya/restaurant-team-e2e.md`](restaurant-team-e2e.md) | How to provision a preserved restaurant signer in Keycast for Synvya server E2E |
| [`docs/synvya/server-e2e-handoff.md`](server-e2e-handoff.md) | Concrete handoff instructions for the `Synvya/server` coding session |
| [`Synvya/mcp-server` — Thin Client Migration](https://github.com/Synvya/mcp-server/blob/main/docs/specs/thin-client-migration.md) | MCP migration toward thin Server-backed APIs |

## What Keycast Owns

- email/password and imported-key authentication
- session/token handling
- encrypted private-key custody
- RPC methods for signing and NIP-44 encrypt/decrypt
- team-based restaurant identities used by both client and server
- hosted endpoints on `auth.staging.synvya.com` and `auth.synvya.com`

## What Keycast Does Not Own

- reservation state
- NIP-RP business workflows
- NIP-65 routing resolution
- public Nostr discovery caching
- MCP/OpenAPI request translation

Those responsibilities belong to the Server and downstream adapter services.

## Identity Split

Synvya uses two distinct identity layers:

- **personal user identities** in Keycast for humans logging into the client app
- **team-owned restaurant identities** in Keycast for restaurant-scoped publishing and always-on automation

The client represents humans. The server represents the always-on restaurant operational actor. Both depend on Keycast to act as the restaurant identity without exposing the restaurant private key.

## Deployment Boundary

- Keycast remains its own service on `auth.*`
- The Server is a separate service on `server.*`
- The Server calls Keycast over HTTPS for auth introspection and signing/decryption RPC
- AWS WAF sits in front of both ALBs, rate-limiting email-triggering endpoints and blocking known bot IPs

## What Synvya Needs From Keycast

- AWS KMS encryption provider
- AWS SES email provider
- stable auth and signing RPC surface
- deployable AWS hosting for Keycast itself
- support for background provisioning of server-side restaurant authorizations
- bot-resistant email endpoints (via AWS WAF rate limiting)
