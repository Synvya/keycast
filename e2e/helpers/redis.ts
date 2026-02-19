import Redis from "ioredis";

// Hardcoded to local test instance — never use env vars to avoid leaking production credentials
const REDIS_URL = "redis://localhost:16379";

export async function withRedis<T>(
  fn: (redis: Redis) => Promise<T>,
): Promise<T> {
  const redis = new Redis(REDIS_URL);
  try {
    return await fn(redis);
  } finally {
    redis.disconnect();
  }
}

export async function addSupportAdmin(pubkey: string) {
  return withRedis((r) => r.sadd("support_admins", pubkey));
}

export async function removeSupportAdmin(pubkey: string) {
  return withRedis((r) => r.srem("support_admins", pubkey));
}

export async function clearSupportAdmins() {
  return withRedis((r) => r.del("support_admins"));
}
