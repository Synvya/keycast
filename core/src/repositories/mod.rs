// ABOUTME: Repository module for data access operations
// ABOUTME: Provides abstraction layer between handlers and database

mod atproto_oauth_session;
mod authorization;
mod claim_token;
mod customer_app_origin;
mod deletion_notice;
mod error;
mod magic_link_token;
mod oauth_authorization;
mod oauth_code;
mod personal_keys;
mod policy;
mod refresh_token;
mod registered_client;
mod stored_key;
mod team;
mod team_invitation;
mod user;

pub use atproto_oauth_session::{
    AtprotoOAuthSession, AtprotoOAuthSessionRepository, CreateAtprotoOAuthSessionParams,
    IssueAtprotoTokensParams,
};
pub use authorization::AuthorizationRepository;
pub use claim_token::ClaimTokenRepository;
pub use customer_app_origin::{CustomerAppOrigin, CustomerAppOriginRepository};
pub use deletion_notice::{DeletionNotice, DeletionNoticeRepository};
pub use error::RepositoryError;
pub use magic_link_token::{
    hash_magic_link_token, ConsumedMagicLink, MagicLinkTokenRepository, PURPOSE_DELETE_ACCOUNT,
    PURPOSE_SIGN_IN,
};
pub use oauth_authorization::{CreateOAuthAuthorizationParams, OAuthAuthorizationRepository};
pub use oauth_code::{
    OAuthCodeData, OAuthCodeRepository, StoreOAuthCodeParams, StoreOAuthCodeWithRegistrationParams,
};
pub use personal_keys::PersonalKeysRepository;
pub use policy::PolicyRepository;
pub use refresh_token::RefreshTokenRepository;
pub use registered_client::RegisteredClientRepository;
pub use stored_key::StoredKeyRepository;
pub use team::{RestaurantKeySummary, TeamRepository, TeamSearchResult};
pub use team_invitation::TeamInvitationRepository;
pub use user::{AdminUserDetails, DeleteAccountResult, UserRepository, VerificationTokenData};
