# Synvya Server E2E Handoff

This document is the handoff for the `Synvya/server` coding session that needs to validate restaurant signing end-to-end against Keycast.

Use it together with [`restaurant-team-e2e.md`](restaurant-team-e2e.md). That document explains how Keycast provisions the preserved restaurant signer. This document explains what the server session needs to build and verify.

## Goal

Prove that `Synvya/server` can act as a NIP-46 bunker client for a restaurant that already published events with an existing Nostr key.

The passing condition is simple:

1. Keycast provisions a team-owned restaurant signer from an existing `nsec`
2. `Synvya/server` receives the returned `bunkerUrl`
3. the server uses that bunker URL to call `get_public_key` and `sign_event`
4. the final event pubkey matches the preserved restaurant pubkey from Keycast

The server must not require the raw restaurant `nsec`.

## Read These First

In `keycast`:

- [`docs/synvya/restaurant-team-e2e.md`](restaurant-team-e2e.md)
- [`e2e/helpers/restaurant-team.ts`](../../e2e/helpers/restaurant-team.ts)
- [`e2e/helpers/synvya-server.ts`](../../e2e/helpers/synvya-server.ts)
- [`docs/synvya/architecture-context.md`](architecture-context.md)

Outside this repo:

- [`Synvya/server` server spec](https://github.com/Synvya/server/blob/main/docs/specs/server.md)
- [`Synvya/docs` auth and realtime architecture](https://github.com/Synvya/docs/blob/main/architecture/auth-and-realtime.md)

## Keycast Test Contract

Keycast already contains a provisioning helper for this exact case:

- `provisionRestaurantTeam(request, opts?)`

It returns:

- `sessionCookie`
- `teamId`
- `policyId`
- `restaurantPubkey`
- `authorizationId`
- `bunkerUrl`
- `adminPubkey`

The important value for the server is `bunkerUrl`.

That helper:

1. logs in through the whitelisted E2E admin
2. creates a team
3. imports `E2E_DEMO_RESTAURANT_NSEC` as a team key
4. creates a Keycast authorization for that imported key
5. verifies that the imported key pubkey matches the pubkey derived from the restaurant secret

So the server test does not need to care about raw key import. It only needs to consume the resulting bunker URL and prove signing works correctly.

## What The Server Session Should Build

The server coding session should implement an end-to-end test harness with this shape:

1. start Keycast locally in E2E mode
2. provision the restaurant signer in Keycast
3. start `Synvya/server` with the provisioned `bunkerUrl`
4. exercise a server endpoint or internal test hook that publishes a restaurant-scoped event
5. assert that the signed event pubkey equals `restaurantPubkey`

The server test should also verify identity separation:

- the restaurant signer pubkey is not the same as the human admin pubkey
- the server signs as the restaurant identity, not as a personal user

## Recommended Server Wiring

The cleanest server-side contract is:

- one test-only config input for the restaurant bunker URL
- one optional test-only config input for the Keycast base URL

Use environment variables unless the server already has a better test configuration pattern.

Recommended names, matching the helper in this repo:

- `SYNVYA_RESTAURANT_BUNKER_URL`
- `KEYCAST_BASE_URL`

If the server uses different names, keep them documented and adapt the test harness.

The server should read the bunker URL once at startup and initialize its bunker client from that value.

## Recommended Test Shape

The fastest useful E2E is an API-first integration test, not a browser flow.

Suggested structure in `Synvya/server`:

1. test setup starts Keycast or points at a local Keycast instance
2. setup calls into the Keycast provisioning helper or equivalent provisioning script
3. setup starts the server with `SYNVYA_RESTAURANT_BUNKER_URL=<bunkerUrl>`
4. the test triggers a menu-item publish or equivalent restaurant event
5. the test captures the resulting signed event
6. assertions verify the event pubkey

If the server publishes asynchronously:

- wait for the event to appear in the queue, database, or outbound transport
- assert the final signed event pubkey, not only that the bunker client connected

## Minimum Assertions

Every end-to-end test for this flow should assert all of the following:

1. `bunkerUrl` is accepted by the server
2. the server can call `get_public_key` successfully
3. `get_public_key` returns the expected `restaurantPubkey`
4. a signed restaurant event is produced
5. the signed event `pubkey` equals `restaurantPubkey`
6. the signed event `pubkey` does not equal the human admin pubkey

## Suggested Prompt For The Server Coding Session

Pass this to the `Synvya/server` session:

> Implement an API-first E2E test proving that `Synvya/server` can sign as a preserved restaurant identity through Keycast. Use the Keycast docs at `docs/synvya/restaurant-team-e2e.md` and `docs/synvya/server-e2e-handoff.md`, plus the helper contracts in `e2e/helpers/restaurant-team.ts` and `e2e/helpers/synvya-server.ts`. The test should provision a restaurant signer in Keycast from `E2E_DEMO_RESTAURANT_NSEC`, inject the returned `bunkerUrl` into the server, trigger one restaurant-scoped publish path, and assert that the emitted event pubkey equals the preserved restaurant pubkey and differs from the human admin pubkey. Do not require the raw `nsec` in the server repo. Prefer a test-only server startup/config hook over production code changes.

## What Not To Build

Do not build:

- a server flow that imports the raw restaurant `nsec`
- a test that signs as the human admin account
- a UI-driven flow as the first implementation
- a Keycast backend change for this path unless the existing helper proves insufficient

## Environment Needed

Keycast-side E2E needs:

- `E2E_DEMO_RESTAURANT_NSEC`
- `BUNKER_RELAYS`

Server-side E2E usually needs:

- `SYNVYA_RESTAURANT_BUNKER_URL`
- `KEYCAST_BASE_URL`
- whatever server-local database or app config is already required for integration tests

## Completion Checklist

The server session is done when:

- the server can boot with a supplied restaurant bunker URL
- a test path causes the server to sign a restaurant-scoped event
- the test proves the event pubkey equals the preserved restaurant pubkey
- the test documents how to run the flow locally
