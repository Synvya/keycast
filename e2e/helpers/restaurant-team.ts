import { APIRequestContext } from "@playwright/test";
import { nip19 } from "nostr-tools";
import { getPublicKey } from "nostr-tools/pure";
import { parseCookieValue } from "./auth";
import { ADMIN_PUBKEY, registerAdmin } from "./admin";

interface TeamResponse {
  team: {
    id: number;
    name: string;
  };
  policies: Array<{
    policy: {
      id: number;
      name: string;
    };
  }>;
}

interface StoredKeyResponse {
  id: number;
  team_id: number;
  name: string;
  pubkey: string;
}

interface AuthorizationCreatedResponse {
  id: number;
  bunker_url: string;
}

export interface ProvisionRestaurantTeamResult {
  sessionCookie: string;
  teamId: number;
  policyId: number;
  restaurantPubkey: string;
  authorizationId: number;
  bunkerUrl: string;
  adminPubkey?: string;
}

export interface ProvisionRestaurantTeamOptions {
  teamName?: string;
  keyLabel?: string;
  relays?: string[];
  authorizationLabel?: string;
}

function requireDemoRestaurantSecret(): string {
  const nsec = process.env.E2E_DEMO_RESTAURANT_NSEC?.trim();
  if (!nsec) {
    throw new Error(
      "Missing E2E_DEMO_RESTAURANT_NSEC environment variable. Set it to the demo restaurant nsec before running this test.",
    );
  }
  return nsec;
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error("Secret key must be a valid 64-character hex string");
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}

function decodeSecretKey(secret: string): Uint8Array {
  const normalized = secret.trim();

  if (normalized.startsWith("nsec1")) {
    const decoded = nip19.decode(normalized);
    if (decoded.type !== "nsec" || !(decoded.data instanceof Uint8Array)) {
      throw new Error("E2E_DEMO_RESTAURANT_NSEC must decode to a valid nsec secret key");
    }
    return decoded.data;
  }

  return hexToBytes(normalized);
}

function deriveRestaurantPubkey(secret: string): string {
  return getPublicKey(decodeSecretKey(secret));
}

function defaultRelays(): string[] {
  const configured = process.env.BUNKER_RELAYS
    ?.split(",")
    .map((relay) => relay.trim())
    .filter(Boolean);

  if (!configured || configured.length === 0) {
    throw new Error(
      "Missing BUNKER_RELAYS environment variable. Set it so the helper can create a matching team authorization.",
    );
  }

  return configured;
}

async function readJson<T>(response: Awaited<ReturnType<APIRequestContext["get"]>>): Promise<T> {
  return (await response.json()) as T;
}

async function expectOk(
  response: Awaited<ReturnType<APIRequestContext["get"]>>,
  action: string,
): Promise<void> {
  if (!response.ok()) {
    const body = await response.text();
    throw new Error(`${action} failed (${response.status()}): ${body}`);
  }
}

export async function provisionRestaurantTeam(
  request: APIRequestContext,
  opts: ProvisionRestaurantTeamOptions = {},
): Promise<ProvisionRestaurantTeamResult> {
  const restaurantSecret = requireDemoRestaurantSecret();
  const restaurantPubkey = deriveRestaurantPubkey(restaurantSecret);
  const relays = opts.relays ?? defaultRelays();

  const { cookie } = await registerAdmin(request);
  const sessionCookie = `keycast_session=${parseCookieValue(cookie)}`;

  const teamName =
    opts.teamName ??
    `e2e-restaurant-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const keyLabel = opts.keyLabel ?? "Imported Restaurant Key";
  const authorizationLabel = opts.authorizationLabel ?? "E2E Restaurant Authorization";

  const createTeamRes = await request.post("/api/teams", {
    headers: { Cookie: sessionCookie },
    data: { name: teamName },
  });
  await expectOk(createTeamRes, "Create team");

  const createdTeam = await readJson<TeamResponse>(createTeamRes);
  const teamId = createdTeam.team.id;

  const getTeamRes = await request.get(`/api/teams/${teamId}`, {
    headers: { Cookie: sessionCookie },
  });
  await expectOk(getTeamRes, "Fetch team");

  const team = await readJson<TeamResponse>(getTeamRes);
  const defaultPolicy = team.policies.find(
    (policy) => policy.policy.name === "All Access",
  );
  if (!defaultPolicy) {
    throw new Error(
      `Team ${teamId} did not include the default 'All Access' policy needed for authorization creation.`,
    );
  }

  const addKeyRes = await request.post(`/api/teams/${teamId}/keys`, {
    headers: { Cookie: sessionCookie },
    data: {
      name: keyLabel,
      secret_key: restaurantSecret,
    },
  });
  await expectOk(addKeyRes, "Import restaurant team key");

  const storedKey = await readJson<StoredKeyResponse>(addKeyRes);
  if (storedKey.pubkey !== restaurantPubkey) {
    throw new Error(
      `Imported restaurant key pubkey mismatch. Expected ${restaurantPubkey}, got ${storedKey.pubkey}.`,
    );
  }

  const createAuthorizationRes = await request.post(
    `/api/teams/${teamId}/keys/${restaurantPubkey}/authorizations`,
    {
      headers: { Cookie: sessionCookie },
      data: {
        policy_id: defaultPolicy.policy.id,
        relays,
        label: authorizationLabel,
      },
    },
  );
  await expectOk(createAuthorizationRes, "Create restaurant team authorization");

  const authorization =
    await readJson<AuthorizationCreatedResponse>(createAuthorizationRes);

  return {
    sessionCookie,
    teamId,
    policyId: defaultPolicy.policy.id,
    restaurantPubkey,
    authorizationId: authorization.id,
    bunkerUrl: authorization.bunker_url,
    adminPubkey: ADMIN_PUBKEY,
  };
}
