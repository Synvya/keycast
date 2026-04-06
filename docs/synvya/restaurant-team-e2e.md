# Synvya Restaurant Team E2E with Keycast

This document explains how to use the Playwright helper in [`e2e/helpers/restaurant-team.ts`](../../e2e/helpers/restaurant-team.ts) to provision a restaurant identity in Keycast and hand the resulting bunker URL to the Synvya server, which acts as the bunker client.

For process-level Synvya integration tests, use the companion harness in [`e2e/helpers/synvya-server.ts`](../../e2e/helpers/synvya-server.ts).

If you need to hand this off to a `Synvya/server` implementation session, start with [`server-e2e-handoff.md`](server-e2e-handoff.md).

## What This Helper Does

`provisionRestaurantTeam()` creates the exact Keycast state needed for a restaurant-scoped signing test:

1. logs in through the existing whitelisted E2E admin account
2. creates a Keycast team for the restaurant
3. reads the team's default `All Access` policy
4. imports the restaurant's existing `nsec` as a team key
5. creates a team authorization for that imported key
6. returns the `bunkerUrl` and related IDs for test code

This is the correct Synvya model when:

- the restaurant already published events with its own Nostr key
- that key must stay the same
- Synvya server should sign on behalf of the restaurant through Keycast

The helper does not create a personal Keycast identity for the restaurant. It provisions a team-owned restaurant signer and keeps the human admin separate.

## Required Environment

The helper requires these values to be present in the E2E environment:

- `E2E_DEMO_RESTAURANT_NSEC`
- `BUNKER_RELAYS`

`E2E_DEMO_RESTAURANT_NSEC` must be the real restaurant key you want to preserve for the demo environment. The helper derives the expected pubkey locally and fails if Keycast imports a different pubkey.

`BUNKER_RELAYS` must match the relays that the local Keycast instance advertises in bunker URLs. In local E2E this is typically:

```bash
BUNKER_RELAYS=ws://localhost:8080
```

## Running Keycast and the E2E Test

Start Keycast locally:

```bash
cd /Users/alejandro/Synvya/keycast
export E2E_DEMO_RESTAURANT_NSEC='nsec1...'
docker compose -f docker-compose.deps.yml --profile e2e up -d --wait
test -f master.key || ./scripts/generate_key.sh
cargo build --bin keycast

DATABASE_URL=postgres://postgres:password@localhost/keycast \
REDIS_URL=redis://localhost:16379 \
MASTER_KEY_PATH=./master.key \
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:5174,http://localhost:3000 \
SERVER_NSEC=0000000000000000000000000000000000000000000000000000000000000001 \
WEB_BUILD_DIR=./web/build \
BUNKER_RELAYS=ws://localhost:8080 \
ALLOWED_PUBKEYS=25fa07621969c92191feb4433fca94fdb500f2b445fd4f017c0a332ceecbf813 \
./target/debug/keycast
```

In a second terminal, run the dedicated spec:

```bash
cd /Users/alejandro/Synvya/keycast/e2e
npx playwright test tests/restaurant-team.spec.ts
```

If you want to provision the signer and print the returned values for manual server testing, run:

```bash
cd /Users/alejandro/Synvya/keycast/e2e
KEYCAST_BASE_URL='http://localhost:3000' \
BUNKER_RELAYS='ws://localhost:8080' \
E2E_DEMO_RESTAURANT_NSEC='nsec1...' \
npm run provision:restaurant
```

That command prints:

- `bunkerUrl`
- `restaurantPubkey`
- `teamId`
- `policyId`
- `authorizationId`
- `sessionCookie`
- shell `export` lines you can paste into another terminal

If `tsx` is not installed yet in `e2e/`, run `npm install` first.

Run only the preservation test:

```bash
npx playwright test tests/restaurant-team.spec.ts -g "restaurant team import preserves restaurant pubkey"
```

## Using the Helper in a Test

Example Playwright usage:

```ts
import { test, expect } from "@playwright/test";
import { provisionRestaurantTeam } from "../helpers/restaurant-team";

test("provision restaurant signer", async ({ request }) => {
  const provisioned = await provisionRestaurantTeam(request);

  expect(provisioned.restaurantPubkey).toMatch(/^[0-9a-f]{64}$/);
  expect(provisioned.bunkerUrl).toMatch(/^bunker:\/\//);
});
```

Returned values:

- `sessionCookie`: admin session used to provision Keycast resources
- `teamId`: Keycast team ID for the restaurant
- `policyId`: default `All Access` policy used for the authorization
- `restaurantPubkey`: preserved pubkey derived from `E2E_DEMO_RESTAURANT_NSEC`
- `authorizationId`: created Keycast authorization ID
- `bunkerUrl`: NIP-46 bunker URL for the restaurant signer
- `adminPubkey`: the human E2E admin pubkey, useful for separation assertions

## Using It with Synvya Server as the Bunker Client

The intended Synvya E2E shape is:

1. use `provisionRestaurantTeam()` to create the restaurant signer in Keycast
2. pass `provisioned.bunkerUrl` into the Synvya server test harness
3. start or configure the Synvya server so its signer component connects to that bunker URL
4. exercise the server path that publishes or signs restaurant events
5. assert the resulting event pubkey is `provisioned.restaurantPubkey`

In other words, Keycast is the signer host and Synvya server is the NIP-46 client.

### Expected Server Wiring

The Synvya server test harness should accept a bunker URL as input. For example:

- environment variable injected before process start
- test-only config file
- explicit constructor parameter in the server's signing service

The important contract is:

- the server should treat the bunker URL as the restaurant signing credential
- the server should not need the raw `nsec`
- the server should use the bunker for `get_public_key` and `sign_event`

### Typical Test Flow

```ts
const provisioned = await provisionRestaurantTeam(request);

const server = await startSynvyaServer({
  cwd: "/path/to/Synvya/server",
  command: "bun",
  args: ["run", "dev:test"],
  baseUrl: "http://127.0.0.1:4000",
  restaurantBunkerUrl: provisioned.bunkerUrl,
});

try {
  const result = await publishRestaurantMenuItem(...);
  expect(result.pubkey).toBe(provisioned.restaurantPubkey);
} finally {
  await server.stop();
}
```

If the Synvya server publishes through a queue or background worker, the test should wait for the signed event to be emitted and verify the final event pubkey rather than only checking that the bunker client connected.

### Companion Harness

`startSynvyaServer()` is a generic process harness for Synvya server integration tests. It does four things:

1. spawns the server process in the requested working directory
2. injects the Keycast bunker URL into the server environment
3. optionally injects the Keycast base URL
4. waits for the server healthcheck before returning control to the test

Default environment variable names:

- `SYNVYA_RESTAURANT_BUNKER_URL`
- `KEYCAST_BASE_URL`

You can override both names if the Synvya server uses different config keys.

Example:

```ts
import { startSynvyaServer } from "../helpers/synvya-server";
import { provisionRestaurantTeam } from "../helpers/restaurant-team";

const provisioned = await provisionRestaurantTeam(request);

const server = await startSynvyaServer({
  cwd: "/path/to/Synvya/server",
  command: "bun",
  args: ["run", "dev:test"],
  baseUrl: "http://127.0.0.1:4000",
  keycastBaseUrl: process.env.API_URL || "http://127.0.0.1:3000",
  restaurantBunkerUrl: provisioned.bunkerUrl,
});

try {
  const response = await fetch(`${server.baseUrl}/internal/test/publish-menu-item`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      title: "Test Menu Item",
    }),
  });
  const event = await response.json();

  expect(event.pubkey).toBe(provisioned.restaurantPubkey);
} finally {
  await server.stop();
}
```

## What to Assert in Synvya E2E

For a full server integration test, assert all of the following:

- the imported restaurant pubkey matches the legacy restaurant pubkey
- the Synvya server reads the bunker URL successfully
- the Synvya server can call `get_public_key` through the bunker client
- signed restaurant events come back with `restaurantPubkey`
- the server is not signing as the human admin identity

## Operational Notes

- Do not commit the real demo restaurant `nsec` into the repo.
- This helper is only suitable for restaurants whose private key is available.
- If a partner restaurant's `nsec` is unavailable, you cannot preserve its existing pubkey with this flow.
- The helper uses the whitelisted E2E admin account because team creation in this repo is admin-gated.

## Failure Modes

The helper intentionally fails fast when:

- `E2E_DEMO_RESTAURANT_NSEC` is missing
- `BUNKER_RELAYS` is missing
- the team does not expose the default `All Access` policy
- the imported team key pubkey does not match the pubkey derived from the supplied `nsec`

Those are configuration or provisioning errors and should be fixed before debugging the Synvya server's bunker client.
