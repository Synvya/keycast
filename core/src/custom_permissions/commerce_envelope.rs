use crate::{
    custom_permissions::PermissionDisplay,
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};

/// The Open Markets private commerce envelope. Encrypted, never signed.
const COMMERCE_ENVELOPE_KIND: u16 = 1327;
/// The seal around each envelope.
const SEAL_KIND: u16 = 13;

/// The envelope extension that names the person who sent a message for an organization.
const SENT_BY_EXTENSION: &str = "openmarkets:sent_by";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommerceEnvelopeConfig {
    pub merchant_pubkey: String,
    /// Set on a grant on a team key: the personal key of the member the grant belongs to. Every
    /// envelope must then name that member in its `openmarkets:sent_by` extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_by: Option<String>,
}

/// Lets an orders app place orders for a customer with one merchant, and nothing else.
pub struct CommerceEnvelope {
    merchant_pubkey: PublicKey,
    sent_by: Option<PublicKey>,
}

impl CommerceEnvelope {
    /// Whether the plaintext is an unsigned commerce envelope addressed to the merchant, and,
    /// on a team key, sent by the grant's member.
    fn is_envelope_for_merchant(&self, plaintext: &str) -> bool {
        match serde_json::from_str::<UnsignedEvent>(plaintext) {
            Ok(event) => {
                event.kind.as_u16() == COMMERCE_ENVELOPE_KIND
                    && event
                        .tags
                        .public_keys()
                        .any(|pubkey| *pubkey == self.merchant_pubkey)
                    && self.is_sent_by_member(&event.content)
            }
            Err(_) => false,
        }
    }

    /// The envelope's content is its payload as JSON. On a team key its
    /// `extensions["openmarkets:sent_by"].pubkey` must be the member's key, in lowercase hex.
    fn is_sent_by_member(&self, content: &str) -> bool {
        let Some(member) = &self.sent_by else {
            return true;
        };
        serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|payload| {
                payload
                    .get("extensions")?
                    .get(SENT_BY_EXTENSION)?
                    .get("pubkey")?
                    .as_str()
                    .map(|pubkey| pubkey == member.to_hex())
            })
            .unwrap_or(false)
    }
}

#[async_trait]
impl CustomPermission for CommerceEnvelope {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let config: CommerceEnvelopeConfig = serde_json::from_value(permission.config.0.clone())
            .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;
        let merchant_pubkey = PublicKey::from_hex(&config.merchant_pubkey).map_err(|e| {
            PermissionError::InvalidConfig(format!("Invalid merchant_pubkey: {}", e))
        })?;
        let sent_by = config
            .sent_by
            .as_deref()
            .map(PublicKey::from_hex)
            .transpose()
            .map_err(|e| PermissionError::InvalidConfig(format!("Invalid sent_by: {}", e)))?;
        Ok(Box::new(Self {
            merchant_pubkey,
            sent_by,
        }))
    }

    fn identifier(&self) -> &'static str {
        "commerce_envelope"
    }

    fn can_sign(&self, event: &UnsignedEvent) -> bool {
        event.kind.as_u16() == SEAL_KIND
    }

    fn can_encrypt(
        &self,
        plaintext: &str,
        sender_pubkey: &PublicKey,
        recipient_pubkey: &PublicKey,
    ) -> bool {
        // To the merchant, or to the customer's own key for their copy of the message
        (*recipient_pubkey == self.merchant_pubkey || *recipient_pubkey == *sender_pubkey)
            && self.is_envelope_for_merchant(plaintext)
    }

    // Replies arrive in gift wraps from throwaway keys, so the sender is never known in advance
    fn can_decrypt(
        &self,
        _ciphertext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }

    fn display(&self) -> PermissionDisplay {
        PermissionDisplay {
            icon: "🛒",
            title: "Place orders",
            description: "Can place orders with this merchant and read the replies".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::permission::JsonConfig;
    use chrono::Utc;
    use nostr_sdk::{EventBuilder, Keys, Kind, Tag};
    use serde_json::json;

    fn permission(config: serde_json::Value) -> Permission {
        Permission {
            id: 1,
            identifier: "commerce_envelope".to_string(),
            config: JsonConfig(config),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    struct Fixture {
        permission: Box<dyn CustomPermission>,
        customer: PublicKey,
        merchant: PublicKey,
        other: PublicKey,
    }

    fn fixture() -> Fixture {
        let merchant = Keys::generate().public_key();
        Fixture {
            permission: permission(json!({ "merchant_pubkey": merchant.to_hex() }))
                .to_custom_permission()
                .expect("Valid config should load"),
            customer: Keys::generate().public_key(),
            merchant,
            other: Keys::generate().public_key(),
        }
    }

    fn message(kind: u16, author: PublicKey, p_tags: &[PublicKey]) -> String {
        let event = EventBuilder::new(Kind::from(kind), "order")
            .tags(p_tags.iter().map(|pubkey| Tag::public_key(*pubkey)))
            .build(author);
        serde_json::to_string(&event).unwrap()
    }

    #[test]
    fn test_encrypts_an_envelope_to_the_merchant() {
        let f = fixture();
        let plaintext = message(1327, f.customer, &[f.merchant]);
        assert!(f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.merchant));
    }

    #[test]
    fn test_encrypts_the_customers_own_copy() {
        let f = fixture();
        let plaintext = message(1327, f.customer, &[f.merchant]);
        assert!(f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.customer));
    }

    #[test]
    fn test_finds_the_merchant_among_several_p_tags() {
        let f = fixture();
        let plaintext = message(1327, f.customer, &[f.other, f.merchant]);
        assert!(f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.merchant));
    }

    #[test]
    fn test_refuses_another_recipient() {
        let f = fixture();
        let plaintext = message(1327, f.customer, &[f.merchant]);
        assert!(!f.permission.can_encrypt(&plaintext, &f.customer, &f.other));
    }

    #[test]
    fn test_refuses_an_envelope_naming_another_merchant() {
        let f = fixture();
        let plaintext = message(1327, f.customer, &[f.other]);
        assert!(!f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.merchant));
        assert!(!f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.customer));
    }

    #[test]
    fn test_refuses_an_envelope_naming_no_merchant() {
        let f = fixture();
        let plaintext = message(1327, f.customer, &[]);
        assert!(!f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.merchant));
    }

    #[test]
    fn test_refuses_any_other_kind() {
        let f = fixture();
        for kind in [1, 4, 13, 14, 1059] {
            let plaintext = message(kind, f.customer, &[f.merchant]);
            assert!(
                !f.permission
                    .can_encrypt(&plaintext, &f.customer, &f.merchant),
                "kind {kind} to the merchant"
            );
            assert!(
                !f.permission
                    .can_encrypt(&plaintext, &f.customer, &f.customer),
                "kind {kind} to the customer's own key"
            );
        }
    }

    #[test]
    fn test_refuses_a_plaintext_that_is_not_an_event() {
        let f = fixture();
        for plaintext in ["hello", "", "{}", r#"{"kind":1327}"#] {
            assert!(
                !f.permission
                    .can_encrypt(plaintext, &f.customer, &f.merchant),
                "{plaintext:?}"
            );
        }
    }

    #[test]
    fn test_signs_only_seals() {
        let f = fixture();
        let seal = EventBuilder::new(Kind::from(13), "sealed").build(f.customer);
        assert!(f.permission.can_sign(&seal));

        for kind in [0, 1, 3, 4, 1059, 1327] {
            let event = EventBuilder::new(Kind::from(kind), "x").build(f.customer);
            assert!(!f.permission.can_sign(&event), "kind {kind}");
        }
    }

    #[test]
    fn test_decrypts_from_any_sender() {
        let f = fixture();
        assert!(f
            .permission
            .can_decrypt("ciphertext", &f.other, &f.customer));
        assert!(f
            .permission
            .can_decrypt("ciphertext", &f.merchant, &f.customer));
    }

    #[test]
    fn test_config_without_a_valid_merchant_is_an_error() {
        for config in [
            json!({}),
            json!({ "merchant_pubkey": "not-a-pubkey" }),
            json!({ "merchant_pubkey": "" }),
        ] {
            assert!(
                permission(config.clone()).to_custom_permission().is_err(),
                "{config}"
            );
        }
    }

    fn team_permission(merchant: PublicKey, member: PublicKey) -> Box<dyn CustomPermission> {
        permission(json!({ "merchant_pubkey": merchant.to_hex(), "sent_by": member.to_hex() }))
            .to_custom_permission()
            .expect("Valid team config should load")
    }

    fn envelope_with_content(author: PublicKey, merchant: PublicKey, content: String) -> String {
        let event = EventBuilder::new(Kind::from(1327), content)
            .tags([Tag::public_key(merchant)])
            .build(author);
        serde_json::to_string(&event).unwrap()
    }

    fn sent_by(pubkey: &str) -> String {
        json!({
            "items": [],
            "extensions": { "openmarkets:sent_by": { "pubkey": pubkey } }
        })
        .to_string()
    }

    #[test]
    fn test_team_key_encrypts_an_envelope_sent_by_the_member() {
        let team = Keys::generate().public_key();
        let merchant = Keys::generate().public_key();
        let member = Keys::generate().public_key();
        let permission = team_permission(merchant, member);

        let plaintext = envelope_with_content(team, merchant, sent_by(&member.to_hex()));
        assert!(permission.can_encrypt(&plaintext, &team, &merchant));
        assert!(
            permission.can_encrypt(&plaintext, &team, &team),
            "The team's own copy"
        );
    }

    #[test]
    fn test_team_key_refuses_an_envelope_sent_by_another_member() {
        let team = Keys::generate().public_key();
        let merchant = Keys::generate().public_key();
        let member = Keys::generate().public_key();
        let other = Keys::generate().public_key();
        let permission = team_permission(merchant, member);

        let plaintext = envelope_with_content(team, merchant, sent_by(&other.to_hex()));
        assert!(!permission.can_encrypt(&plaintext, &team, &merchant));
        assert!(!permission.can_encrypt(&plaintext, &team, &team));
    }

    #[test]
    fn test_team_key_refuses_an_envelope_without_sent_by() {
        let team = Keys::generate().public_key();
        let merchant = Keys::generate().public_key();
        let member = Keys::generate().public_key();
        let permission = team_permission(merchant, member);

        for content in [
            "order".to_string(),
            json!({ "items": [] }).to_string(),
            json!({ "extensions": {} }).to_string(),
            json!({ "extensions": { "openmarkets:sent_by": {} } }).to_string(),
            json!({ "extensions": { "openmarkets:sent_by": { "pubkey": 7 } } }).to_string(),
            // At the top level, not in extensions
            json!({ "openmarkets:sent_by": { "pubkey": member.to_hex() } }).to_string(),
            // Upper case is not the member's key as the shape requires it
            sent_by(&member.to_hex().to_uppercase()),
        ] {
            let plaintext = envelope_with_content(team, merchant, content.clone());
            assert!(
                !permission.can_encrypt(&plaintext, &team, &merchant),
                "{content}"
            );
        }
    }

    #[test]
    fn test_personal_grant_ignores_sent_by() {
        let f = fixture();
        let other = Keys::generate().public_key();
        let plaintext = envelope_with_content(f.customer, f.merchant, sent_by(&other.to_hex()));
        assert!(f
            .permission
            .can_encrypt(&plaintext, &f.customer, &f.merchant));
    }

    #[test]
    fn test_config_with_an_invalid_sent_by_is_an_error() {
        let merchant = Keys::generate().public_key().to_hex();
        let config = json!({ "merchant_pubkey": merchant, "sent_by": "not-a-pubkey" });
        assert!(permission(config).to_custom_permission().is_err());
    }

    #[test]
    fn test_is_listed_as_available() {
        assert!(crate::custom_permissions::AVAILABLE_PERMISSIONS.contains(&"commerce_envelope"));
    }
}
