// ABOUTME: Per-IP and per-email limits for endpoints that send email or call KMS
// ABOUTME: Limits fail open when Redis is unavailable, so an outage does not stop sign-in

use crate::redis::PrefixedRedis;
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// The client's IP. The ALB appends it to X-Forwarded-For, so only the last entry can be
/// trusted; earlier entries are whatever the caller sent.
pub fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .rsplit(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

/// A Redis key part for an email address, so addresses are not stored in Redis.
pub fn email_key(email: &str) -> String {
    hex::encode(Sha256::digest(email.as_bytes()))
}

/// At most one event per window for this key. Returns true if this one is allowed.
pub async fn once_per_window(
    redis: Option<&PrefixedRedis>,
    key: &str,
    window_seconds: u64,
) -> bool {
    let Some(redis) = redis else {
        return true;
    };
    match redis.set_nx_ex(key, "1", window_seconds).await {
        Ok(allowed) => allowed,
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            true
        }
    }
}

/// At most `limit` events per window for this key. Returns true if this one is allowed.
pub async fn under_limit(
    redis: Option<&PrefixedRedis>,
    key: &str,
    limit: u64,
    window_seconds: u64,
) -> bool {
    let Some(redis) = redis else {
        return true;
    };
    match redis.incr_with_ttl(key, window_seconds).await {
        Ok(count) => count <= limit,
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());
        headers
    }

    #[test]
    fn test_client_ip_uses_the_entry_the_load_balancer_appended() {
        assert_eq!(
            client_ip(&headers("203.0.113.7")),
            Some("203.0.113.7".parse().unwrap())
        );
        assert_eq!(
            client_ip(&headers("198.51.100.1, 10.0.0.1, 203.0.113.7")),
            Some("203.0.113.7".parse().unwrap()),
            "A caller can send any earlier entries"
        );
    }

    #[test]
    fn test_client_ip_is_none_when_absent_or_invalid() {
        assert_eq!(client_ip(&HeaderMap::new()), None);
        assert_eq!(client_ip(&headers("not-an-ip")), None);
    }

    #[test]
    fn test_email_key_does_not_contain_the_address() {
        let key = email_key("dana@example.com");
        assert!(!key.contains("dana"));
        assert_eq!(key, email_key("dana@example.com"));
    }

    #[tokio::test]
    async fn test_limits_allow_when_redis_is_absent() {
        assert!(once_per_window(None, "key", 60).await);
        assert!(under_limit(None, "key", 1, 60).await);
    }
}
