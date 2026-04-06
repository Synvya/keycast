import { expect, test } from "@playwright/test";
import { connectToBunker } from "../helpers/nip46";
import { provisionRestaurantTeam } from "../helpers/restaurant-team";

test.describe("Restaurant team provisioning", () => {
  test.setTimeout(120_000);

  test("restaurant team import preserves restaurant pubkey", async ({ request }) => {
    const provisioned = await provisionRestaurantTeam(request);

    if (provisioned.adminPubkey) {
      expect(provisioned.restaurantPubkey).not.toBe(provisioned.adminPubkey);
    }

    const client = await connectToBunker(provisioned.bunkerUrl);
    try {
      const signerPubkey = await client.getPublicKey();
      expect(signerPubkey).toBe(provisioned.restaurantPubkey);

      const signed = await client.signEvent({
        kind: 1,
        content: "Restaurant team signer identity preservation test",
        tags: [],
        created_at: Math.floor(Date.now() / 1000),
      });

      expect(signed.id).toMatch(/^[0-9a-f]{64}$/);
      expect(signed.sig).toMatch(/^[0-9a-f]{128}$/);
      expect(signed.pubkey).toBe(provisioned.restaurantPubkey);
      expect(signed.content).toBe(
        "Restaurant team signer identity preservation test",
      );
    } finally {
      await client.close();
    }
  });

  test("human admin remains separate from restaurant signer", async ({ request }) => {
    const provisioned = await provisionRestaurantTeam(request);

    expect(provisioned.adminPubkey).toBeTruthy();
    expect(provisioned.restaurantPubkey).not.toBe(provisioned.adminPubkey);
  });
});
