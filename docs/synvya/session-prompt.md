# Keycast Implementation — Session Prompt

Copy everything below the line and paste it as the opening message in a new Claude Code session with the working directory set to `/Users/alejandro/Synvya/keycast`.

---

## Project Context

I'm deploying Keycast (a Nostr key custody and authentication service) on AWS as part of Synvya's restaurant platform. The repo at `/Users/alejandro/Synvya/keycast` is a fork of `divinevideo/keycast`. All architecture decisions and specs are already written — your job is to implement them.

## Read These First

Before writing any code, read these documents in order:

1. **Fork workflow and branching strategy**: `SYNVYA.md` (repo root)
2. **Architecture context and links to all specs**: `docs/synvya/architecture-context.md`
3. **AWS KMS provider spec**: `docs/synvya/aws-kms-provider.md`
4. **AWS SES email provider spec**: `docs/synvya/aws-ses-provider.md`
5. **EC2 deployment spec**: `docs/synvya/ec2-deployment.md`
6. **Existing Keycast CLAUDE.md**: `CLAUDE.md` (repo root)

Also read the existing code you'll be modifying:
- `core/src/encryption/mod.rs` (KeyManager trait)
- `core/src/encryption/aws_key_manager.rs` (stub to implement)
- `core/src/encryption/gcp_key_manager.rs` (reference implementation to follow)
- `core/src/encryption/file_key_manager.rs` (reference implementation)
- `api/src/email_service.rs` (EmailSender trait + SendGrid + Dev implementations)
- `keycast/src/main.rs` (provider selection at startup, around lines 260-275 and 440-455)
- `core/Cargo.toml` (dependencies)

## Implementation Order

There are three features to implement. Do them in this order:

### 1. AWS KMS Provider (`feat/aws-kms` branch, from `main`)

This is an upstream contribution — NO Synvya-specific code. Follow the spec in `docs/synvya/aws-kms-provider.md`:

- Implement `AwsKeyManager` in `core/src/encryption/aws_key_manager.rs`
- Add `aws` Cargo feature flag gating `aws-sdk-kms` and `aws-config`
- Gate the module with `#[cfg(feature = "aws")]`
- Update `main.rs`: replace `USE_GCP_KMS` boolean with `KMS_PROVIDER` env var (backward-compatible)
- Add integration test gated behind `AWS_KMS_KEY_ID`
- Forward the feature flag in `keycast/Cargo.toml`

### 2. AWS SES Email Provider (`feat/aws-ses` branch, from `main`)

This is also an upstream contribution — NO Synvya-specific code. Follow the spec in `docs/synvya/aws-ses-provider.md`:

- Extract hardcoded HTML/text email templates from `SendGridEmailSender` into shared functions (pure refactor first)
- Implement `SesEmailSender` using `aws-sdk-sesv2`, gated behind the `aws` feature
- Update `create_email_sender()`: replace implicit SendGrid detection with `EMAIL_PROVIDER` env var (backward-compatible)
- Forward the feature flag in `keycast/Cargo.toml` to include `keycast_api/aws`

### 3. EC2 Deployment (`synvya/*` branch, from `synvya-staging`)

This is Synvya-specific. Follow the spec in `docs/synvya/ec2-deployment.md`:

- Create `docker-compose.synvya.yml`
- Modify `Dockerfile` to accept `CARGO_FEATURES` build arg
- Create `scripts/load-secrets.sh` (environment-aware: staging vs prod)
- Create `scripts/backup-postgres.sh`
- Create `.github/workflows/deploy-staging.yml`
- Create `.github/workflows/deploy-prod.yml`

## Key Rules

- **Read SYNVYA.md carefully** — it defines which branch to use for each type of work
- `feat/aws-*` branches come from `main` and must contain zero Synvya references
- `synvya/*` branches come from `synvya-staging`
- Follow the GCP KMS implementation patterns exactly (retry logic, logging, error handling)
- Do NOT modify the `KeyManager` or `EmailSender` trait interfaces
- The `aws` feature flag must be optional — default builds should work without AWS SDK

## Workflow per Feature

For `feat/aws-*` branches (KMS, SES):
1. Create the branch from `main`
2. Implement the full feature per the spec
3. Run `cargo check --features aws` and `cargo test` to verify
4. Commit with clear messages and push to origin
5. Do NOT create a PR to `divinevideo/keycast` — I will do that manually after review
6. Merge the feature branch into `synvya-staging` so we can use it in staging:
   ```
   git checkout synvya-staging
   git merge feat/aws-<feature>
   git push origin synvya-staging
   ```
7. Move immediately to the next feature

For `synvya/*` branches (EC2 deployment):
1. Create the branch from `synvya-staging`
2. Implement the full feature per the spec
3. Commit with clear messages and push to origin
4. Create internal PR: `gh pr create --base synvya-staging`
5. Merge the PR into `synvya-staging`

## Start

Work through all three features (KMS → SES → EC2 deployment) without stopping. Do not ask me questions — if something is ambiguous, make a reasonable decision based on the specs and document what you chose in the commit message. Read all the specs and code listed above, then begin with step 1 (AWS KMS).
