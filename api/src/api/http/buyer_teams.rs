// ABOUTME: Buyer teams on the customer tenant: a team with its own key, members who order as it
// ABOUTME: Customer routes for the buyer app, admin routes for Synvya Server, and the team grant

use super::admin::{customer_tenant_id, is_full_admin, is_support_admin};
use super::auth::{generate_secure_token, generate_server_signed_ucan, token_expiry_seconds};
use super::confirmations::{parse_body, require_confirmation, ConfirmedChange};
use super::magic_link::{allowed_app_url, merchant_for_grant, normalize_email, CommerceGrant};
use super::routes::AuthState;
use crate::api::error::{ApiError, ApiResult};
use crate::api::extractors::UcanAuth;
use crate::api::tenant::TenantExtractor;
use crate::email_service::EmailService;
use crate::handlers::http_rpc_handler::invalidate_handlers_for_bunker;
use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use keycast_core::authorization_channel::AuthorizationCommand;
use keycast_core::bunker_key::derive_bunker_keys;
use keycast_core::repositories::{
    find_team_signing, list_team_events, record_team_event, BuyerTeam, BuyerTeamInvitation,
    BuyerTeamMember, BuyerTeamMembership, BuyerTeamRepository, LastAdmin, MemberChange,
    TeamDeletion, TeamEvent, TeamEventRow, TeamInvitationRepository, TeamSigning, UserRepository,
};
use keycast_core::types::authorization::Authorization;
use keycast_core::types::user::BUYER_TEAM_ROLES;
use nostr_sdk::{Keys, PublicKey, Url};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// The name of a team made without one.
const DEFAULT_TEAM_NAME: &str = "Buyer account";
/// The longest team name kept.
const MAX_TEAM_NAME_LENGTH: usize = 200;
/// The only scope a team grant takes, as on email-link sign-in.
const COMMERCE_SCOPE: &str = "policy:commerce_envelope";
/// The query parameter that carries an invitation's token on the buyer app's page.
const INVITE_PARAM: &str = "team_invite";
/// The answer when a change would leave a team with no admin.
const LAST_ADMIN: &str = "last_admin";

// ============================================================================
// Shared parts
// ============================================================================

/// The signed-in buyer: their pubkey and the origin their session was issued for.
async fn signed_in_buyer(headers: &HeaderMap, tenant_id: i64) -> ApiResult<(String, String)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::auth("Missing session"))?;
    let (pubkey, redirect_origin, _, _) =
        crate::ucan_auth::validate_ucan_token(auth_header, tenant_id)
            .await
            .map_err(|_| ApiError::auth("Invalid session"))?;
    Ok((pubkey, redirect_origin))
}

fn not_customer_tenant() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn parse_pubkey(value: &str, field: &str) -> ApiResult<String> {
    PublicKey::from_hex(value.trim())
        .map(|pubkey| pubkey.to_hex())
        .map_err(|_| ApiError::bad_request(format!("Invalid {field}")))
}

fn parse_buyer_role(role: &str) -> ApiResult<&str> {
    BUYER_TEAM_ROLES
        .iter()
        .find(|known| **known == role)
        .copied()
        .ok_or_else(|| ApiError::bad_request("role must be admin, orderer or viewer"))
}

fn team_name(name: Option<&str>) -> ApiResult<String> {
    let name = name.map(str::trim).filter(|name| !name.is_empty());
    match name {
        Some(name) if name.chars().count() > MAX_TEAM_NAME_LENGTH => {
            Err(ApiError::bad_request("name is too long"))
        }
        Some(name) => Ok(name.to_string()),
        None => Ok(DEFAULT_TEAM_NAME.to_string()),
    }
}

async fn find_team(pool: &PgPool, tenant_id: i64, team_pubkey: &str) -> ApiResult<BuyerTeam> {
    let team_pubkey = parse_pubkey(team_pubkey, "team_pubkey")?;
    BuyerTeamRepository::new(pool.clone())
        .find_by_pubkey(tenant_id, &team_pubkey)
        .await?
        .ok_or_else(|| ApiError::not_found("Team not found"))
}

/// The caller's role in the team. A person who is not a member learns nothing about the team.
async fn require_member(pool: &PgPool, team: &BuyerTeam, pubkey: &str) -> ApiResult<String> {
    BuyerTeamRepository::new(pool.clone())
        .role_of(team.team_id, pubkey)
        .await?
        .ok_or_else(|| ApiError::not_found("Team not found"))
}

async fn require_admin(pool: &PgPool, team: &BuyerTeam, pubkey: &str) -> ApiResult<()> {
    match require_member(pool, team, pubkey).await?.as_str() {
        "admin" => Ok(()),
        _ => Err(ApiError::forbidden("Only a team admin can do this")),
    }
}

/// Generate a team key, encrypted like every other stored key, and make the team.
async fn make_team(
    auth_state: &AuthState,
    tenant_id: i64,
    name: &str,
    first_admin: Option<&str>,
    actor: Option<&str>,
) -> ApiResult<BuyerTeam> {
    let keys = Keys::generate();
    let encrypted_secret = auth_state
        .state
        .key_manager
        .encrypt(&keys.secret_key().to_secret_bytes())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to encrypt team key: {}", e)))?;
    let team = BuyerTeamRepository::new(auth_state.state.db.clone())
        .create(
            tenant_id,
            name,
            &keys.public_key().to_hex(),
            &encrypted_secret,
            first_admin,
            actor,
        )
        .await?;
    tracing::info!(
        event = "buyer_team_created",
        tenant_id = tenant_id,
        team_id = team.team_id,
        with_admin = first_admin.is_some(),
        "Buyer team created"
    );
    Ok(team)
}

/// Stop the revoked grants at once: drop them from the HTTP RPC cache and from the signer.
async fn forget_grants(auth_state: &AuthState, bunker_pubkeys: &[String]) {
    for bunker_pubkey in bunker_pubkeys {
        invalidate_handlers_for_bunker(&auth_state.state.http_handler_cache, bunker_pubkey);
        if let Some(tx) = &auth_state.auth_tx {
            if let Err(e) = tx
                .send(AuthorizationCommand::Remove {
                    bunker_pubkey: bunker_pubkey.clone(),
                })
                .await
            {
                tracing::warn!("Failed to notify signer of team grant revocation: {}", e);
            }
        }
    }
}

/// The fresh confirmation of a member or role change (store API contract §14.5): `Some(428)`
/// until the request carries a confirmation bound to exactly this method, path and body.
async fn confirmation_for(
    pool: &PgPool,
    headers: &HeaderMap,
    uri: &OriginalUri,
    body: &[u8],
    tenant_id: i64,
    pubkey: &str,
    action: &'static str,
) -> ApiResult<Option<Response>> {
    require_confirmation(
        pool,
        headers,
        &ConfirmedChange {
            tenant_id,
            member_pubkey: pubkey,
            action,
            method: "POST",
            path: uri.0.path(),
            body,
        },
    )
    .await
}

fn member_change_result(change: MemberChange) -> ApiResult<Vec<String>> {
    match change {
        MemberChange::Done { revoked_bunkers } => Ok(revoked_bunkers),
        MemberChange::NotMember => Err(ApiError::not_found("Not a member of this team")),
        MemberChange::LastAdmin => Err(ApiError::conflict(LAST_ADMIN)),
    }
}

// ============================================================================
// The grant on the team key
// ============================================================================

/// Why a team grant was not made.
pub(super) enum TeamGrantError {
    /// The person is not a member of the team, or the team does not exist.
    NotMember,
    Internal(String),
}

/// A grant on the team key for one member and one merchant.
pub(super) struct TeamGrant {
    /// Names the grant, so it works on /api/nostr.
    pub(super) session_token: String,
    pub(super) bunker_url: String,
    /// `commerce_envelope` for an admin or orderer, `decrypt_only` for a viewer.
    pub(super) permission: &'static str,
    pub(super) role: String,
}

/// What a team grant is for.
pub(super) struct TeamGrantRequest<'a> {
    pub(super) tenant_id: i64,
    pub(super) team_pubkey: &'a str,
    pub(super) member_pubkey: &'a str,
    pub(super) member_email: &'a str,
    pub(super) merchant_pubkey: &'a str,
    pub(super) client_id: &'a str,
    pub(super) redirect_uri: &'a str,
}

/// Give a member a grant on the team key. An admin or orderer gets `commerce_envelope` for the
/// merchant, bound to their own key by `sent_by`. A viewer gets `decrypt_only`. Anyone else
/// gets nothing.
pub(super) async fn create_team_grant(
    auth_state: &AuthState,
    request: TeamGrantRequest<'_>,
) -> Result<TeamGrant, TeamGrantError> {
    let internal = |e: &dyn std::fmt::Display| TeamGrantError::Internal(e.to_string());
    let pool = &auth_state.state.db;
    let teams = BuyerTeamRepository::new(pool.clone());

    let team = teams
        .find_by_pubkey(request.tenant_id, request.team_pubkey)
        .await
        .map_err(|e| internal(&e))?
        .ok_or(TeamGrantError::NotMember)?;
    let role = teams
        .role_of(team.team_id, request.member_pubkey)
        .await
        .map_err(|e| internal(&e))?
        .ok_or(TeamGrantError::NotMember)?;

    let (policy_id, permission) = match role.as_str() {
        "admin" | "orderer" => (
            teams
                .find_or_create_member_commerce_policy(
                    team.team_id,
                    request.merchant_pubkey,
                    request.member_pubkey,
                )
                .await
                .map_err(|e| internal(&e))?,
            "commerce_envelope",
        ),
        "viewer" => (
            teams
                .find_or_create_read_policy(team.team_id)
                .await
                .map_err(|e| internal(&e))?,
            "decrypt_only",
        ),
        // An owner-tenant role has no place on a buyer team
        _ => return Err(TeamGrantError::NotMember),
    };

    let secret_pair = crate::state::get_secret_pool()
        .map_err(|e| internal(&e))?
        .get()
        .await
        .ok_or_else(|| TeamGrantError::Internal("Secret pool exhausted".to_string()))?;
    let encrypted_team_key = teams
        .encrypted_team_key(team.stored_key_id)
        .await
        .map_err(|e| internal(&e))?;
    let team_secret = auth_state
        .state
        .key_manager
        .decrypt(&encrypted_team_key)
        .await
        .map_err(|e| internal(&e))?;
    let team_secret = nostr_sdk::SecretKey::from_slice(&team_secret).map_err(|e| internal(&e))?;
    let bunker_keys = derive_bunker_keys(&team_secret, &secret_pair.hash);
    let bunker_pubkey = bunker_keys.public_key().to_hex();

    let relays = serde_json::json!(Authorization::get_bunker_relays());
    let label = format!("buyer:{}:{}", request.member_pubkey, request.client_id);
    let authorization_id = teams
        .create_member_grant(
            request.tenant_id,
            team.stored_key_id,
            policy_id,
            &secret_pair.hash,
            &bunker_pubkey,
            &relays,
            request.member_pubkey,
            &label,
        )
        .await
        .map_err(|e| internal(&e))?;

    if let Some(tx) = &auth_state.auth_tx {
        if let Err(e) = tx
            .send(AuthorizationCommand::Upsert {
                bunker_pubkey: bunker_pubkey.clone(),
                tenant_id: request.tenant_id,
                is_oauth: false,
            })
            .await
        {
            tracing::warn!("Failed to notify signer of team grant: {}", e);
        }
    }

    let member = PublicKey::from_hex(request.member_pubkey).map_err(|e| internal(&e))?;
    let redirect_origin = Url::parse(request.redirect_uri)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| request.redirect_uri.to_string());
    let session_token = generate_server_signed_ucan(
        &member,
        request.tenant_id,
        request.member_email,
        &redirect_origin,
        Some(&bunker_pubkey),
        &auth_state.state.server_keys,
        false,
        None,
    )
    .await
    .map_err(|e| TeamGrantError::Internal(format!("{:?}", e)))?;

    tracing::info!(
        event = "buyer_team_grant_created",
        tenant_id = request.tenant_id,
        team_id = team.team_id,
        authorization_id = authorization_id,
        permission = permission,
        "Team grant created"
    );

    Ok(TeamGrant {
        session_token,
        bunker_url: Authorization::generate_bunker_url(
            &bunker_pubkey,
            secret_pair.secret.expose_secret(),
        ),
        permission,
        role,
    })
}

// ============================================================================
// Customer routes (customer hostname, Bearer session from email-link sign-in)
// ============================================================================

#[derive(Debug, Serialize)]
pub struct CustomerSessionResponse {
    pub pubkey: String,
    pub email: String,
}

/// GET /api/customer/session - whose session this is: the buyer's personal key and email.
/// Synvya Server calls it once with the buyer's Bearer token to make its own buyer session.
/// Any token that does not validate on the customer tenant answers 401.
pub async fn customer_session(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let tenant_id = tenant.0.id;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let email = UserRepository::new(auth_state.state.db.clone())
        .get_email(&pubkey, tenant_id)
        .await
        .map_err(|_| ApiError::auth("Invalid session"))?;
    Ok(Json(CustomerSessionResponse { pubkey, email }).into_response())
}

#[derive(Debug, Serialize)]
pub struct MyTeamsResponse {
    pub teams: Vec<BuyerTeamMembership>,
}

/// GET /api/customer/teams - the buyer teams the signed-in buyer belongs to.
pub async fn list_my_teams(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let tenant_id = tenant.0.id;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let teams = BuyerTeamRepository::new(auth_state.state.db.clone())
        .list_teams_of(tenant_id, &pubkey)
        .await?;
    Ok(Json(MyTeamsResponse { teams }).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreatedTeamResponse {
    pub team_pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_pubkey: Option<String>,
}

/// POST /api/customer/teams - make a buyer team and its key. The caller is its first admin.
pub async fn create_my_team(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<CreateTeamRequest>,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let tenant_id = tenant.0.id;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let name = team_name(req.name.as_deref())?;
    let team = make_team(&auth_state, tenant_id, &name, Some(&pubkey), Some(&pubkey)).await?;
    Ok(Json(CreatedTeamResponse {
        team_pubkey: team.team_pubkey,
        name: team.name,
        role: Some("admin".to_string()),
        admin_pubkey: None,
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct TeamQuery {
    pub team_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct TeamMembersResponse {
    pub team_pubkey: String,
    pub name: String,
    pub members: Vec<BuyerTeamMember>,
}

/// GET /api/customer/teams/members?team_pubkey= - the members of a team the caller belongs to.
pub async fn list_my_team_members(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<TeamQuery>,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let team = find_team(pool, tenant_id, &query.team_pubkey).await?;
    require_member(pool, &team, &pubkey).await?;
    let members = BuyerTeamRepository::new(pool.clone())
        .list_members(tenant_id, team.team_id)
        .await?;
    Ok(Json(TeamMembersResponse {
        team_pubkey: team.team_pubkey,
        name: team.name,
        members,
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub team_pubkey: String,
    pub email: String,
    pub role: String,
    /// The buyer app's page the invitation lands on. Must be on an allowed app origin.
    pub app_url: String,
}

#[derive(Debug, Serialize)]
pub struct InvitedMember {
    pub email: String,
    pub role: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct InviteMemberResponse {
    pub invitation: InvitedMember,
}

/// POST /api/customer/teams/invite - a team admin invites a person by email. The person accepts
/// after signing in with that email.
pub async fn invite_member(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let req: InviteMemberRequest = parse_body(&body)?;
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let team = find_team(pool, tenant_id, &req.team_pubkey).await?;
    require_admin(pool, &team, &pubkey).await?;

    let role = parse_buyer_role(&req.role)?;
    let email = normalize_email(&req.email)
        .ok_or_else(|| ApiError::bad_request("Invalid email address"))?;
    let (app_url, _) = allowed_app_url(pool, tenant_id, &req.app_url)
        .await?
        .ok_or_else(|| ApiError::bad_request("app_url is not allowed"))?;

    let users = UserRepository::new(pool.clone());
    if let Some(existing) = users.find_pubkey_by_email(&email, tenant_id).await? {
        if BuyerTeamRepository::new(pool.clone())
            .role_of(team.team_id, &existing)
            .await?
            .is_some()
        {
            return Err(ApiError::conflict("Already a team member"));
        }
    }

    let invitations = TeamInvitationRepository::new(pool.clone());
    if invitations
        .find_pending_by_email(team.team_id, &email)
        .await?
        .is_some()
    {
        return Err(ApiError::conflict(
            "Invitation already pending for this email",
        ));
    }

    if let Some(required) = confirmation_for(
        pool,
        &headers,
        &uri,
        &body,
        tenant_id,
        &pubkey,
        "team_invite",
    )
    .await?
    {
        return Ok(required);
    }

    let redis = crate::rate_limit::shared_redis();
    if !crate::rate_limit::allow_request(redis, "team_invite", tenant_id, &headers, Some(&email))
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    let token = generate_secure_token();
    let invitation = invitations
        .create(team.team_id, tenant_id, &email, role, &token, &pubkey)
        .await?;
    // The invitation repository keeps its own connection, so the log entry follows it.
    record_team_event(
        pool,
        &TeamEvent {
            tenant_id,
            team_pubkey: &team.team_pubkey,
            action: "invited",
            member_email: Some(&email),
            member_pubkey: None,
            role: Some(role),
            actor_pubkey: Some(&pubkey),
        },
    )
    .await?;

    let mut link = app_url.clone();
    link.set_fragment(None);
    link.query_pairs_mut().append_pair(INVITE_PARAM, &token);
    let inviter = users
        .get_email(&pubkey, tenant_id)
        .await
        .unwrap_or_else(|_| "A team admin".to_string());
    match EmailService::new().await {
        Ok(email_service) => {
            if let Err(e) = email_service
                .send_team_invite_email(
                    &email,
                    &team.name,
                    None,
                    &inviter,
                    role,
                    invitation.expires_at,
                    link.as_str(),
                )
                .await
            {
                tracing::error!("Failed to send buyer team invitation: {}", e);
            }
        }
        Err(e) => tracing::error!("Failed to create email service: {}", e),
    }

    Ok(Json(InviteMemberResponse {
        invitation: InvitedMember {
            email: invitation.email,
            role: invitation.role,
            expires_at: invitation.expires_at,
        },
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct AcceptTeamInvitationRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct AcceptTeamInvitationResponse {
    pub team_pubkey: String,
    pub name: String,
    pub role: String,
}

/// POST /api/customer/teams/accept - join a team with an invitation sent to the caller's email.
pub async fn accept_team_invitation(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<AcceptTeamInvitationRequest>,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;

    let not_found = || ApiError::not_found("Invitation not found or expired");
    let invitations = TeamInvitationRepository::new(pool.clone());
    let invitation = invitations
        .find_valid_by_token(&req.token)
        .await?
        .filter(|invitation| invitation.tenant_id == tenant_id)
        .ok_or_else(not_found)?;
    // A buyer team invitation carries a buyer role; anything else is not one
    parse_buyer_role(&invitation.role).map_err(|_| not_found())?;

    let email = UserRepository::new(pool.clone())
        .get_email(&pubkey, tenant_id)
        .await
        .map_err(|_| ApiError::bad_request("Could not read your email address"))?;
    if email.to_lowercase() != invitation.email.to_lowercase() {
        return Err(ApiError::forbidden(
            "This invitation was sent to a different email address",
        ));
    }

    let team: Option<(String, String)> = sqlx::query_as(
        "SELECT sk.pubkey, t.name FROM teams t
         JOIN stored_keys sk ON sk.team_id = t.id
         WHERE t.id = $1 ORDER BY sk.id LIMIT 1",
    )
    .bind(invitation.team_id)
    .fetch_optional(pool)
    .await?;
    let (team_pubkey, name) = team.ok_or_else(not_found)?;

    let teams = BuyerTeamRepository::new(pool.clone());
    let joined = TeamEvent {
        tenant_id,
        team_pubkey: &team_pubkey,
        action: "joined",
        member_email: None,
        member_pubkey: Some(&pubkey),
        role: Some(&invitation.role),
        actor_pubkey: Some(&pubkey),
    };
    if !teams
        .add_member(invitation.team_id, &pubkey, &invitation.role, Some(&joined))
        .await?
    {
        return Err(ApiError::conflict("You are already a member of this team"));
    }
    invitations.accept(&req.token, &pubkey).await?;

    Ok(Json(AcceptTeamInvitationResponse {
        team_pubkey,
        name,
        role: invitation.role,
    })
    .into_response())
}

/// A refusal in Keycast's flat body, `{ "error", "code" }`, so the client reads the cause from
/// the code and not from the message.
fn coded_refusal(error: ApiError) -> Response {
    let (status, code, message) = match error {
        ApiError::Auth(message) => (StatusCode::UNAUTHORIZED, "unauthorized", message),
        ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, "validation_error", message),
        ApiError::Forbidden(message) => (StatusCode::FORBIDDEN, "forbidden", message),
        ApiError::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message),
        other => {
            tracing::error!("Buyer team invitation route failed: {}", other);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Something went wrong. Please try again.".to_string(),
            )
        }
    };
    (
        status,
        Json(serde_json::json!({ "error": message, "code": code })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct TeamInvitationsQuery {
    pub team_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TeamInvitationsResponse {
    pub invitations: Vec<BuyerTeamInvitation>,
}

/// GET /api/customer/teams/invitations?team_pubkey= - a team admin reads the team's pending
/// member invitations, newest first. 403 for a member who is not an admin, 404 for a team the
/// caller is not on.
pub async fn list_team_invitations(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<TeamInvitationsQuery>,
) -> Response {
    if !tenant.0.is_customer_tenant() {
        return coded_refusal(ApiError::not_found("Not found"));
    }
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let answer: ApiResult<Response> = async {
        let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
        let team_pubkey = query
            .team_pubkey
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("team_pubkey is required"))?;
        let team = find_team(pool, tenant_id, team_pubkey).await?;
        require_admin(pool, &team, &pubkey).await?;
        let invitations = BuyerTeamRepository::new(pool.clone())
            .list_pending_invitations(tenant_id, team.team_id)
            .await?;
        Ok(Json(TeamInvitationsResponse { invitations }).into_response())
    }
    .await;
    answer.unwrap_or_else(coded_refusal)
}

#[derive(Debug, Deserialize)]
pub struct WithdrawInvitationRequest {
    pub team_pubkey: String,
    pub invitation_id: i32,
}

#[derive(Debug, Serialize)]
pub struct WithdrawInvitationResponse {
    pub withdrawn: bool,
}

/// POST /api/customer/teams/invitations/withdraw - a team admin withdraws a pending invitation.
/// Its link then answers 404 at accept, and the team change log gets `invitation_withdrawn`.
/// No fresh confirmation: a withdrawal admits no one.
pub async fn withdraw_team_invitation(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !tenant.0.is_customer_tenant() {
        return coded_refusal(ApiError::not_found("Not found"));
    }
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let answer: ApiResult<Response> = async {
        let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
        let req: WithdrawInvitationRequest = parse_body(&body)?;
        let team = find_team(pool, tenant_id, &req.team_pubkey).await?;
        require_admin(pool, &team, &pubkey).await?;
        if !BuyerTeamRepository::new(pool.clone())
            .withdraw_invitation(tenant_id, &team, req.invitation_id, &pubkey)
            .await?
        {
            return Err(ApiError::not_found("Invitation not found or not pending"));
        }
        tracing::info!(
            event = "buyer_team_invitation_withdrawn",
            tenant_id = tenant_id,
            team_id = team.team_id,
            invitation_id = req.invitation_id,
            "Buyer team invitation withdrawn"
        );
        Ok(Json(WithdrawInvitationResponse { withdrawn: true }).into_response())
    }
    .await;
    answer.unwrap_or_else(coded_refusal)
}

#[derive(Debug, Deserialize)]
pub struct ChangeRoleRequest {
    pub team_pubkey: String,
    pub member_pubkey: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct ChangeRoleResponse {
    pub team_pubkey: String,
    pub member_pubkey: String,
    pub role: String,
}

/// POST /api/customer/teams/role - a team admin changes a member's role. The last admin cannot
/// be demoted.
pub async fn change_member_role(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let req: ChangeRoleRequest = parse_body(&body)?;
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let team = find_team(pool, tenant_id, &req.team_pubkey).await?;
    require_admin(pool, &team, &pubkey).await?;
    let member = parse_pubkey(&req.member_pubkey, "member_pubkey")?;
    let role = parse_buyer_role(&req.role)?;
    if let Some(required) =
        confirmation_for(pool, &headers, &uri, &body, tenant_id, &pubkey, "team_role").await?
    {
        return Ok(required);
    }

    let event = TeamEvent {
        tenant_id,
        team_pubkey: &team.team_pubkey,
        action: "role_set",
        member_email: None,
        member_pubkey: Some(&member),
        role: Some(role),
        actor_pubkey: Some(&pubkey),
    };
    let change = BuyerTeamRepository::new(pool.clone())
        .change_role(&team, &member, role, Some(&event))
        .await?;
    let revoked = member_change_result(change)?;
    forget_grants(&auth_state, &revoked).await;

    Ok(Json(ChangeRoleResponse {
        team_pubkey: team.team_pubkey,
        member_pubkey: member,
        role: role.to_string(),
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct RemoveMemberRequest {
    pub team_pubkey: String,
    pub member_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct RemoveMemberResponse {
    pub removed: bool,
    pub revoked_grants: usize,
}

/// POST /api/customer/teams/remove - a team admin removes a member, or a member leaves. Their
/// grants on the team key end at once. The last admin cannot leave or be removed.
pub async fn remove_member(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let req: RemoveMemberRequest = parse_body(&body)?;
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let (pubkey, _) = signed_in_buyer(&headers, tenant_id).await?;
    let team = find_team(pool, tenant_id, &req.team_pubkey).await?;
    let member = parse_pubkey(&req.member_pubkey, "member_pubkey")?;
    if member == pubkey {
        require_member(pool, &team, &pubkey).await?;
    } else {
        require_admin(pool, &team, &pubkey).await?;
    }
    if let Some(required) = confirmation_for(
        pool,
        &headers,
        &uri,
        &body,
        tenant_id,
        &pubkey,
        "team_remove",
    )
    .await?
    {
        return Ok(required);
    }

    // An admin removing someone, or the member leaving: the actor says which.
    let event = TeamEvent {
        tenant_id,
        team_pubkey: &team.team_pubkey,
        action: "removed",
        member_email: None,
        member_pubkey: Some(&member),
        role: None,
        actor_pubkey: Some(&pubkey),
    };
    let change = BuyerTeamRepository::new(pool.clone())
        .remove_member(&team, &member, LastAdmin::Stays, Some(&event))
        .await?;
    let revoked = member_change_result(change)?;
    forget_grants(&auth_state, &revoked).await;

    Ok(Json(RemoveMemberResponse {
        removed: true,
        revoked_grants: revoked.len(),
    })
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct TeamGrantBody {
    pub team_pubkey: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub merchant_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TeamGrantAuthorization {
    pub bunker_url: String,
}

#[derive(Debug, Serialize)]
pub struct TeamGrantResponse {
    pub team_pubkey: String,
    pub role: String,
    /// `commerce_envelope` or `decrypt_only`
    pub permission: String,
    /// A session that names the grant: use it on /api/nostr.
    pub session_token: String,
    pub expires_in: i64,
    pub authorization: TeamGrantAuthorization,
}

/// POST /api/customer/teams/grant - a grant on the team key for the merchant of the app the
/// caller signed in at. Admin and orderer get `commerce_envelope`; a viewer gets `decrypt_only`.
pub async fn grant_on_team_key(
    tenant: TenantExtractor,
    State(auth_state): State<AuthState>,
    headers: HeaderMap,
    Json(req): Json<TeamGrantBody>,
) -> ApiResult<Response> {
    if !tenant.0.is_customer_tenant() {
        return Ok(not_customer_tenant());
    }
    let tenant_id = tenant.0.id;
    let pool = &auth_state.state.db;
    let (pubkey, session_origin) = signed_in_buyer(&headers, tenant_id).await?;

    if req.client_id.trim().is_empty() {
        return Err(ApiError::bad_request("Invalid client_id"));
    }
    if req.scope != COMMERCE_SCOPE {
        return Err(ApiError::bad_request("Invalid scope"));
    }
    let team_pubkey = parse_pubkey(&req.team_pubkey, "team_pubkey")?;
    let merchant_pubkey = req
        .merchant_pubkey
        .as_deref()
        .map(|merchant| {
            PublicKey::from_hex(merchant)
                .map_err(|_| ApiError::bad_request("Invalid merchant_pubkey"))
        })
        .transpose()?;
    let grant = CommerceGrant {
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        merchant_pubkey,
    };
    // The merchant of the app the session was issued at, from the approved list
    let merchant = merchant_for_grant(pool, tenant_id, &session_origin, &grant)
        .await
        .map_err(|e| match e {
            super::auth::AuthError::BadRequest(msg) => ApiError::bad_request(msg),
            other => ApiError::internal(format!("{:?}", other)),
        })?;

    let email = UserRepository::new(pool.clone())
        .get_email(&pubkey, tenant_id)
        .await
        .map_err(|_| ApiError::auth("Invalid session"))?;

    let created = create_team_grant(
        &auth_state,
        TeamGrantRequest {
            tenant_id,
            team_pubkey: &team_pubkey,
            member_pubkey: &pubkey,
            member_email: &email,
            merchant_pubkey: &merchant,
            client_id: &req.client_id,
            redirect_uri: &req.redirect_uri,
        },
    )
    .await
    .map_err(|e| match e {
        TeamGrantError::NotMember => ApiError::forbidden("Not a member of this team"),
        TeamGrantError::Internal(msg) => ApiError::internal(msg),
    })?;

    Ok(Json(TeamGrantResponse {
        team_pubkey,
        role: created.role,
        permission: created.permission.to_string(),
        session_token: created.session_token,
        expires_in: token_expiry_seconds(),
        authorization: TeamGrantAuthorization {
            bunker_url: created.bunker_url,
        },
    })
    .into_response())
}

// ============================================================================
// Admin routes (another hostname, full admin: Synvya Server over NIP-98)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AdminCreateTeamRequest {
    pub name: Option<String>,
    /// The first admin, by email or by pubkey. Neither makes a team with no member.
    pub admin_email: Option<String>,
    pub admin_pubkey: Option<String>,
}

/// A customer of the customer tenant, named by email or by pubkey. None when neither is given.
async fn find_customer(
    pool: &PgPool,
    tenant_id: i64,
    email: Option<&str>,
    pubkey: Option<&str>,
) -> ApiResult<Option<String>> {
    match (email, pubkey) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(ApiError::bad_request("Send an email or a pubkey, not both")),
        (Some(email), None) => {
            let email =
                normalize_email(email).ok_or_else(|| ApiError::bad_request("Invalid email"))?;
            UserRepository::new(pool.clone())
                .find_pubkey_by_email(&email, tenant_id)
                .await?
                .map(Some)
                .ok_or_else(|| ApiError::not_found("No customer with this email"))
        }
        (None, Some(pubkey)) => {
            let pubkey = parse_pubkey(pubkey, "pubkey")?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE pubkey = $1 AND tenant_id = $2)",
            )
            .bind(&pubkey)
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;
            if exists {
                Ok(Some(pubkey))
            } else {
                Err(ApiError::not_found("No customer with this pubkey"))
            }
        }
    }
}

fn require_full_admin(auth: &UcanAuth) -> ApiResult<()> {
    if is_full_admin(auth) {
        Ok(())
    } else {
        Err(ApiError::forbidden("Admin access required"))
    }
}

/// POST /api/admin/customer-teams - make a buyer team and its key, with a first admin or with
/// no member (a store invitation not yet accepted).
pub async fn admin_create_team(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Json(req): Json<AdminCreateTeamRequest>,
) -> ApiResult<Json<CreatedTeamResponse>> {
    require_full_admin(&auth)?;
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let name = team_name(req.name.as_deref())?;
    let admin = find_customer(
        pool,
        tenant_id,
        req.admin_email.as_deref(),
        req.admin_pubkey.as_deref(),
    )
    .await?;
    let team = make_team(&auth_state, tenant_id, &name, admin.as_deref(), None).await?;
    Ok(Json(CreatedTeamResponse {
        team_pubkey: team.team_pubkey,
        name: team.name,
        role: None,
        admin_pubkey: admin,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CustomerTeamsQuery {
    pub email: Option<String>,
    pub pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CustomerTeamsResponse {
    pub pubkey: String,
    pub teams: Vec<BuyerTeamMembership>,
}

/// GET /api/admin/customer-teams?email=|pubkey= - the buyer teams a customer belongs to.
pub async fn admin_list_customer_teams(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Query(query): Query<CustomerTeamsQuery>,
) -> ApiResult<Json<CustomerTeamsResponse>> {
    require_full_admin(&auth)?;
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let pubkey = find_customer(
        pool,
        tenant_id,
        query.email.as_deref(),
        query.pubkey.as_deref(),
    )
    .await?
    .ok_or_else(|| ApiError::bad_request("Send an email or a pubkey"))?;
    let teams = BuyerTeamRepository::new(pool.clone())
        .list_teams_of(tenant_id, &pubkey)
        .await?;
    Ok(Json(CustomerTeamsResponse { pubkey, teams }))
}

/// GET /api/admin/customer-teams/:team_pubkey/members - a team's members.
pub async fn admin_list_team_members(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path(team_pubkey): Path<String>,
) -> ApiResult<Json<TeamMembersResponse>> {
    require_full_admin(&auth)?;
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let team = find_team(pool, tenant_id, &team_pubkey).await?;
    let members = BuyerTeamRepository::new(pool.clone())
        .list_members(tenant_id, team.team_id)
        .await?;
    Ok(Json(TeamMembersResponse {
        team_pubkey: team.team_pubkey,
        name: team.name,
        members,
    }))
}

/// DELETE /api/admin/customer-teams/:team_pubkey/members/:member_pubkey - remove a member and
/// revoke their grants on the team key: a buyer account closed. The last admin may go only when
/// no other member remains, so the team is left empty with its key, never with members and no
/// admin.
pub async fn admin_remove_team_member(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path((team_pubkey, member_pubkey)): Path<(String, String)>,
) -> ApiResult<Json<RemoveMemberResponse>> {
    require_full_admin(&auth)?;
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let team = find_team(pool, tenant_id, &team_pubkey).await?;
    let member = parse_pubkey(&member_pubkey, "member_pubkey")?;
    let event = TeamEvent {
        tenant_id,
        team_pubkey: &team.team_pubkey,
        action: "removed",
        member_email: None,
        member_pubkey: Some(&member),
        role: None,
        actor_pubkey: None,
    };
    let change = BuyerTeamRepository::new(pool.clone())
        .remove_member(&team, &member, LastAdmin::MayLeaveAnEmptyTeam, Some(&event))
        .await?;
    let revoked = member_change_result(change)?;
    forget_grants(&auth_state, &revoked).await;
    tracing::info!(
        event = "buyer_team_member_removed",
        tenant_id = tenant_id,
        team_id = team.team_id,
        member = &member[..8],
        caller = &auth.pubkey[..8.min(auth.pubkey.len())],
        "Buyer team member removed by the admin API"
    );
    Ok(Json(RemoveMemberResponse {
        removed: true,
        revoked_grants: revoked.len(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct AdminAddAdminRequest {
    pub email: Option<String>,
    pub pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminAddAdminResponse {
    pub team_pubkey: String,
    pub admin_pubkey: String,
}

/// POST /api/admin/customer-teams/:team_pubkey/admins - make a customer an admin of the team:
/// a store invitation accepted, or the support restore. Adds them, or raises their role.
pub async fn admin_add_team_admin(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path(team_pubkey): Path<String>,
    Json(req): Json<AdminAddAdminRequest>,
) -> ApiResult<Json<AdminAddAdminResponse>> {
    require_full_admin(&auth)?;
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let team = find_team(pool, tenant_id, &team_pubkey).await?;
    let admin = find_customer(pool, tenant_id, req.email.as_deref(), req.pubkey.as_deref())
        .await?
        .ok_or_else(|| ApiError::bad_request("Send an email or a pubkey"))?;
    BuyerTeamRepository::new(pool.clone())
        .make_admin(tenant_id, &team, &admin)
        .await?;
    tracing::info!(
        event = "buyer_team_admin_added",
        tenant_id = tenant_id,
        team_id = team.team_id,
        admin = &admin[..8],
        caller = &auth.pubkey[..8.min(auth.pubkey.len())],
        "Buyer team admin added by the admin API"
    );
    Ok(Json(AdminAddAdminResponse {
        team_pubkey: team.team_pubkey,
        admin_pubkey: admin,
    }))
}

/// DELETE /api/admin/customer-teams/:team_pubkey - delete a team that has no member, with its
/// key (a store invitation withdrawn).
pub async fn admin_delete_team(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path(team_pubkey): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    require_full_admin(&auth)?;
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let team = find_team(pool, tenant_id, &team_pubkey).await?;
    match BuyerTeamRepository::new(pool.clone())
        .delete_if_empty(tenant_id, &team)
        .await?
    {
        TeamDeletion::Deleted { revoked_bunkers } => {
            forget_grants(&auth_state, &revoked_bunkers).await;
            Ok(Json(serde_json::json!({ "deleted": true })))
        }
        TeamDeletion::HasMembers => Err(ApiError::conflict("Team still has members")),
    }
}

/// The most entries one read of the team change log answers.
const TEAM_EVENTS_MAX: i64 = 500;
const TEAM_EVENTS_DEFAULT: i64 = 100;

/// The reads of the logs are open to support admins as well as full admins.
fn require_support_admin_sync(is_admin: bool) -> ApiResult<()> {
    if is_admin {
        Ok(())
    } else {
        Err(ApiError::forbidden("Admin access required"))
    }
}

#[derive(Debug, Deserialize)]
pub struct TeamEventsQuery {
    pub after: Option<i64>,
    /// ISO 8601. Used only when `after` is absent or 0: the first read from a point in time.
    pub since: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TeamEventsResponse {
    pub events: Vec<TeamEventRow>,
    /// The last id answered, or `after` when nothing is newer: the next read's `after`.
    pub next_after: i64,
}

/// GET /api/admin/customer-team-events?after=&limit= - the team change log of the customer
/// tenant, in id order (account-activity.md AA-7). Synvya Server reads it on a sweep and writes
/// the member records of the account activity.
pub async fn admin_list_team_events(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Query(query): Query<TeamEventsQuery>,
) -> ApiResult<Json<TeamEventsResponse>> {
    require_support_admin_sync(is_support_admin(&auth).await)?;
    let after = query.after.unwrap_or(0).max(0);
    let limit = query
        .limit
        .unwrap_or(TEAM_EVENTS_DEFAULT)
        .clamp(1, TEAM_EVENTS_MAX);
    let since = match (after, query.since.as_deref()) {
        (0, Some(value)) => Some(
            DateTime::parse_from_rfc3339(value)
                .map_err(|_| ApiError::bad_request("since must be an ISO 8601 time"))?
                .with_timezone(&Utc),
        ),
        _ => None,
    };
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    let events = list_team_events(pool, tenant_id, after, since, limit).await?;
    let next_after = events.last().map_or(after, |e| e.id);
    Ok(Json(TeamEventsResponse { events, next_after }))
}

/// GET /api/admin/customer-signing-activity/:event_id - the signing log row of one event a team
/// key signed under a member's grant: who sent a disputed message (buyer-team-keys.md §5.7).
pub async fn admin_get_signing_activity(
    State(auth_state): State<AuthState>,
    auth: UcanAuth,
    Path(event_id): Path<String>,
) -> ApiResult<Json<TeamSigning>> {
    require_support_admin_sync(is_support_admin(&auth).await)?;
    // An event id is 32 bytes of hex, but not a public key: no curve check.
    let event_id = event_id.trim().to_ascii_lowercase();
    if event_id.len() != 64 || !event_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("Invalid event_id"));
    }
    let pool = &auth_state.state.db;
    let tenant_id = customer_tenant_id(pool).await?;
    find_team_signing(pool, tenant_id, &event_id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("No signature of a team key with this event id"))
}
