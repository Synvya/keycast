// ABOUTME: Per-IP and per-email limits for endpoints that send email or call KMS
// ABOUTME: Limits fail open when Redis is unavailable, so an outage does not stop sign-in

use crate::redis::PrefixedRedis;
use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Requests per email per hour on the endpoints that send email or call KMS.
pub const EMAIL_LIMIT_PER_HOUR: u64 = 5;
/// Requests per IP per hour on those endpoints, unless RATE_LIMIT_IP_PER_HOUR says otherwise.
/// Generous, because owners and CI runs can share an address.
const DEFAULT_IP_LIMIT_PER_HOUR: u64 = 60;
const HOUR_SECONDS: u64 = 3600;

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

fn ip_limit_per_hour() -> u64 {
    std::env::var("RATE_LIMIT_IP_PER_HOUR")
        .ok()
        .and_then(|limit| limit.parse().ok())
        .unwrap_or(DEFAULT_IP_LIMIT_PER_HOUR)
}

/// The Redis key counting requests from an IP to one endpoint.
pub fn ip_limit_key(route: &str, tenant_id: i64, ip: IpAddr) -> String {
    format!("rate_limit:{route}:{tenant_id}:ip:{ip}")
}

/// The Redis key counting requests for an email to one endpoint.
pub fn email_limit_key(route: &str, tenant_id: i64, email: &str) -> String {
    format!(
        "rate_limit:{route}:{tenant_id}:email:{}",
        email_key(&email.trim().to_lowercase())
    )
}

/// Apply the per-IP and per-email limits for one endpoint. Returns true if the request may go on.
///
/// Call this before looking anything up, so that being refused says nothing about an account.
pub async fn allow_request(
    redis: Option<&PrefixedRedis>,
    route: &str,
    tenant_id: i64,
    headers: &HeaderMap,
    email: Option<&str>,
) -> bool {
    if let Some(ip) = client_ip(headers) {
        let key = ip_limit_key(route, tenant_id, ip);
        if !under_limit(redis, &key, ip_limit_per_hour(), HOUR_SECONDS).await {
            tracing::warn!(
                "Rate limit reached on {}: too many requests from one IP",
                route
            );
            return false;
        }
    }

    if let Some(email) = email {
        let key = email_limit_key(route, tenant_id, email);
        if !under_limit(redis, &key, EMAIL_LIMIT_PER_HOUR, HOUR_SECONDS).await {
            tracing::warn!(
                "Rate limit reached on {}: too many requests for one email",
                route
            );
            return false;
        }
    }

    true
}

/// The Redis connection for handlers whose state does not carry one.
pub fn shared_redis() -> Option<&'static PrefixedRedis> {
    crate::state::get_keycast_state()
        .ok()
        .and_then(|state| state.redis.as_ref())
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
