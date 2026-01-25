/**
 * Vine Import Script Example
 *
 * This is a reference implementation for bulk importing Vine accounts to Nostr
 * via the Keycast Admin API.
 *
 * Usage:
 *   ADMIN_TOKEN=xxx KEYCAST_URL=https://login.divine.video bun run vine-import-example.ts
 */

// ============================================================================
// Types
// ============================================================================

interface VineUser {
  id: string;
  username: string;
  displayName?: string;
  bio?: string;
  avatarUrl?: string;
  videos?: VineVideo[];
}

interface VineVideo {
  id: string;
  title?: string;
  description?: string;
  videoUrl: string;
  thumbnailUrl?: string;
  duration?: number;
  createdAt?: number; // Unix timestamp
}

interface PreloadUserResponse {
  pubkey: string;
  token: string;
}

interface ClaimTokenResponse {
  claim_url: string;
  expires_at: string;
}

interface SignedEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

interface ImportResult {
  vineId: string;
  pubkey: string;
  claimUrl: string;
  eventsPublished: number;
  error?: string;
}

// ============================================================================
// Configuration
// ============================================================================

const KEYCAST_URL = process.env.KEYCAST_URL || "https://login.divine.video";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const RELAY_URL = process.env.RELAY_URL || "wss://relay.divine.video";
const CONCURRENCY = parseInt(process.env.CONCURRENCY || "10", 10);

if (!ADMIN_TOKEN) {
  console.error("Error: ADMIN_TOKEN environment variable is required");
  console.error("Get one from https://login.divine.video/admin");
  process.exit(1);
}

// ============================================================================
// Keycast API Client
// ============================================================================

class KeycastClient {
  constructor(
    private baseUrl: string,
    private adminToken: string
  ) {}

  /**
   * Create a preloaded user account
   */
  async createPreloadedUser(
    vineId: string,
    username: string,
    displayName?: string
  ): Promise<PreloadUserResponse> {
    const response = await fetch(`${this.baseUrl}/api/admin/preload-user`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        vine_id: vineId,
        username: username,
        display_name: displayName,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to create user: ${response.status} ${error}`);
    }

    return response.json();
  }

  /**
   * Sign a Nostr event using the user's token
   */
  async signEvent(
    userToken: string,
    unsignedEvent: {
      kind: number;
      content: string;
      created_at: number;
      tags: string[][];
    }
  ): Promise<SignedEvent> {
    const response = await fetch(`${this.baseUrl}/api/nostr`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${userToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        method: "sign_event",
        params: [unsignedEvent],
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to sign event: ${response.status} ${error}`);
    }

    const data = await response.json();
    return data.result;
  }

  /**
   * Generate a claim link for account recovery
   */
  async createClaimToken(vineId: string): Promise<ClaimTokenResponse> {
    const response = await fetch(`${this.baseUrl}/api/admin/claim-tokens`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ vine_id: vineId }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to create claim token: ${response.status} ${error}`);
    }

    return response.json();
  }
}

// ============================================================================
// Nostr Relay Publisher
// ============================================================================

class RelayPublisher {
  private ws: WebSocket | null = null;
  private connected = false;
  private messageQueue: SignedEvent[] = [];

  constructor(private relayUrl: string) {}

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.relayUrl);

      this.ws.onopen = () => {
        this.connected = true;
        console.log(`Connected to relay: ${this.relayUrl}`);
        resolve();
      };

      this.ws.onerror = (error) => {
        reject(new Error(`WebSocket error: ${error}`));
      };

      this.ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data.toString());
          if (data[0] === "OK") {
            // Event accepted
          } else if (data[0] === "NOTICE") {
            console.warn(`Relay notice: ${data[1]}`);
          }
        } catch {
          // Ignore parse errors
        }
      };
    });
  }

  async publish(event: SignedEvent): Promise<void> {
    if (!this.connected || !this.ws) {
      throw new Error("Not connected to relay");
    }

    const message = JSON.stringify(["EVENT", event]);
    this.ws.send(message);
  }

  close(): void {
    if (this.ws) {
      this.ws.close();
      this.connected = false;
    }
  }
}

// ============================================================================
// Event Builders
// ============================================================================

function buildProfileEvent(user: VineUser): {
  kind: number;
  content: string;
  created_at: number;
  tags: string[][];
} {
  const profile: Record<string, string> = {
    name: user.displayName || user.username,
  };

  if (user.bio) profile.about = user.bio;
  if (user.avatarUrl) profile.picture = user.avatarUrl;

  return {
    kind: 0,
    content: JSON.stringify(profile),
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
  };
}

function buildVideoEvent(video: VineVideo): {
  kind: number;
  content: string;
  created_at: number;
  tags: string[][];
} {
  const tags: string[][] = [
    ["d", video.id],
    ["url", video.videoUrl],
    ["m", "video/mp4"],
  ];

  if (video.title) tags.push(["title", video.title]);
  if (video.thumbnailUrl) tags.push(["thumb", video.thumbnailUrl]);
  if (video.duration) tags.push(["duration", String(video.duration)]);

  return {
    kind: 34236, // Short video (NIP-71) - Vine = original short-form video
    content: video.description || "",
    created_at: video.createdAt || Math.floor(Date.now() / 1000),
    tags,
  };
}

// ============================================================================
// Import Logic
// ============================================================================

async function importVineUser(
  client: KeycastClient,
  publisher: RelayPublisher,
  user: VineUser
): Promise<ImportResult> {
  try {
    // 1. Create preloaded account
    const account = await client.createPreloadedUser(
      user.id,
      user.username,
      user.displayName
    );

    let eventsPublished = 0;

    // 2. Sign and publish profile event
    const profileEvent = buildProfileEvent(user);
    const signedProfile = await client.signEvent(account.token, profileEvent);
    await publisher.publish(signedProfile);
    eventsPublished++;

    // 3. Sign and publish video events
    for (const video of user.videos || []) {
      const videoEvent = buildVideoEvent(video);
      const signedVideo = await client.signEvent(account.token, videoEvent);
      await publisher.publish(signedVideo);
      eventsPublished++;
    }

    // 4. Generate claim link
    const claimData = await client.createClaimToken(user.id);

    return {
      vineId: user.id,
      pubkey: account.pubkey,
      claimUrl: claimData.claim_url,
      eventsPublished,
    };
  } catch (error) {
    return {
      vineId: user.id,
      pubkey: "",
      claimUrl: "",
      eventsPublished: 0,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// ============================================================================
// Batch Processing with Concurrency Control
// ============================================================================

async function processBatch<T, R>(
  items: T[],
  concurrency: number,
  processor: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = [];
  const executing: Promise<void>[] = [];

  for (const item of items) {
    const promise = processor(item).then((result) => {
      results.push(result);
    });

    executing.push(promise);

    if (executing.length >= concurrency) {
      await Promise.race(executing);
      // Remove completed promises
      const completed = executing.filter(
        (p) => (p as any).settled
      );
      executing.splice(0, executing.length, ...executing.filter((p) => !(p as any).settled));
    }
  }

  await Promise.all(executing);
  return results;
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  // Load Vine data (replace with your actual data source)
  const vineUsers: VineUser[] = [
    // Example data - replace with actual Vine JSON import
    {
      id: "vine_001",
      username: "testuser1",
      displayName: "Test User 1",
      bio: "Original Vine creator",
      avatarUrl: "https://example.com/avatar1.jpg",
      videos: [
        {
          id: "video_001",
          title: "My first vine",
          description: "Check out this vine!",
          videoUrl: "https://cdn.example.com/vine1.mp4",
          thumbnailUrl: "https://cdn.example.com/thumb1.jpg",
          duration: 6,
          createdAt: 1420070400, // 2015-01-01
        },
      ],
    },
  ];

  console.log(`Starting import of ${vineUsers.length} Vine users`);
  console.log(`Keycast URL: ${KEYCAST_URL}`);
  console.log(`Relay URL: ${RELAY_URL}`);
  console.log(`Concurrency: ${CONCURRENCY}`);

  // Initialize clients
  const client = new KeycastClient(KEYCAST_URL, ADMIN_TOKEN!);
  const publisher = new RelayPublisher(RELAY_URL);

  try {
    await publisher.connect();

    // Process users with concurrency control
    const results = await processBatch(
      vineUsers,
      CONCURRENCY,
      (user) => importVineUser(client, publisher, user)
    );

    // Summary
    const successful = results.filter((r) => !r.error);
    const failed = results.filter((r) => r.error);

    console.log("\n=== Import Summary ===");
    console.log(`Total: ${results.length}`);
    console.log(`Successful: ${successful.length}`);
    console.log(`Failed: ${failed.length}`);

    // Output claim URLs for successful imports
    if (successful.length > 0) {
      console.log("\n=== Claim URLs ===");
      for (const result of successful) {
        console.log(`${result.vineId}: ${result.claimUrl}`);
      }
    }

    // Log failures
    if (failed.length > 0) {
      console.log("\n=== Failures ===");
      for (const result of failed) {
        console.log(`${result.vineId}: ${result.error}`);
      }
    }

    // Save results to file
    const outputFile = `import-results-${Date.now()}.json`;
    await Bun.write(outputFile, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to: ${outputFile}`);
  } finally {
    publisher.close();
  }
}

main().catch(console.error);
