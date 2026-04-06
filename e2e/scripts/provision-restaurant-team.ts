import { request as playwrightRequest } from "@playwright/test";
import { ADMIN_PUBKEY } from "../helpers/admin";
import { provisionRestaurantTeam } from "../helpers/restaurant-team";

const DEFAULT_KEYCAST_BASE_URL = "http://localhost:3000";

function shellEscape(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

async function main(): Promise<void> {
  const baseURL = process.env.KEYCAST_BASE_URL?.trim() || DEFAULT_KEYCAST_BASE_URL;

  const request = await playwrightRequest.newContext({
    baseURL,
    extraHTTPHeaders: {
      accept: "application/json",
    },
  });

  try {
    const provisioned = await provisionRestaurantTeam(request);

    const summary = {
      keycastBaseUrl: baseURL,
      teamId: provisioned.teamId,
      policyId: provisioned.policyId,
      authorizationId: provisioned.authorizationId,
      restaurantPubkey: provisioned.restaurantPubkey,
      bunkerUrl: provisioned.bunkerUrl,
      sessionCookie: provisioned.sessionCookie,
      adminPubkey: provisioned.adminPubkey ?? ADMIN_PUBKEY,
    };

    console.log("Provisioned restaurant team signer.");
    console.log("");
    console.log(JSON.stringify(summary, null, 2));
    console.log("");
    console.log("# Shell exports");
    console.log(`export KEYCAST_BASE_URL=${shellEscape(baseURL)}`);
    console.log(`export KEYCAST_TEAM_ID=${provisioned.teamId}`);
    console.log(`export KEYCAST_POLICY_ID=${provisioned.policyId}`);
    console.log(`export KEYCAST_AUTHORIZATION_ID=${provisioned.authorizationId}`);
    console.log(
      `export KEYCAST_RESTAURANT_PUBKEY=${shellEscape(provisioned.restaurantPubkey)}`,
    );
    console.log(
      `export SYNVYA_RESTAURANT_BUNKER_URL=${shellEscape(provisioned.bunkerUrl)}`,
    );
    console.log(
      `export KEYCAST_ADMIN_SESSION_COOKIE=${shellEscape(provisioned.sessionCookie)}`,
    );
    console.log(
      `export KEYCAST_E2E_ADMIN_PUBKEY=${shellEscape(provisioned.adminPubkey ?? ADMIN_PUBKEY)}`,
    );
    console.log("");
    console.log("# Example authenticated team fetch");
    console.log(
      `curl -H "Cookie: ${provisioned.sessionCookie}" ${shellEscape(
        `${baseURL}/api/teams/${provisioned.teamId}`,
      )}`,
    );
    console.log("");
    console.log("# Note");
    console.log(
      "This flow provisions a team authorization. It does not mint a separate OAuth access token.",
    );
  } finally {
    await request.dispose();
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Failed to provision restaurant team signer: ${message}`);
  process.exitCode = 1;
});
