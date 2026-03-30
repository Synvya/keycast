# Synvya Fork — Development Workflow

This repository is a fork of [`divinevideo/keycast`](https://github.com/divinevideo/keycast) maintained by the Synvya organization. It serves two purposes:

1. **Production deployment** — Synvya-specific configuration, AWS infrastructure, deploy scripts
2. **Upstream contributions** — AWS provider implementations (KMS, SES) contributed back to `divinevideo/keycast`

This document defines the branching strategy, development workflow, and rules for keeping these two purposes cleanly separated.

## Remotes

| Remote | URL | Purpose |
|---|---|---|
| `origin` | `https://github.com/Synvya/keycast.git` | Our fork — push here |
| `upstream` | `https://github.com/divinevideo/keycast.git` | Original repo — pull from here, PR to here |

Setup (one-time):
```bash
git remote add upstream https://github.com/divinevideo/keycast.git
git fetch upstream
```

## Branch Strategy

### Protected branches

| Branch | Tracks | Purpose |
|---|---|---|
| `main` | `upstream/main` | Clean mirror of upstream. Never commit Synvya-specific code here. |
| `synvya` | — | Synvya production branch. Contains all upstream code plus Synvya-specific additions. Deploys to `auth.synvya.com`. |

### Working branches

| Branch pattern | Base | PR target | Purpose |
|---|---|---|---|
| `feat/aws-*` | `main` | `divinevideo/keycast` (upstream) | Contributable features (AWS KMS, SES providers) |
| `fix/*` | `main` | `divinevideo/keycast` (upstream) | Bug fixes for upstream |
| `synvya/*` | `synvya` | `Synvya/keycast` (`synvya` branch) | Synvya-specific work (deploy configs, infra, Synvya-only features) |

## Rules

### 1. Keep `main` clean
- `main` must always be a fast-forward of `upstream/main`
- Never commit directly to `main`
- Never merge Synvya-specific code into `main`
- Sync periodically:
  ```bash
  git fetch upstream
  git checkout main
  git merge upstream/main
  git push origin main
  ```

### 2. Contributable work branches off `main`
Any code intended for upstream contribution:
- Branch from `main`
- Contain no Synvya-specific code (no deploy scripts, no Synvya env vars, no Synvya domain references)
- Use Cargo feature flags to gate new dependencies (e.g., `aws = ["aws-sdk-kms", "aws-sdk-ses"]`)
- PR goes to `divinevideo/keycast`, not to `Synvya/keycast`
- After upstream merges, sync `main` and merge into `synvya`

### 3. Synvya-specific work branches off `synvya`
Anything only relevant to Synvya's deployment:
- Branch from `synvya`
- PR goes to `Synvya/keycast` targeting the `synvya` branch
- Examples: Docker Compose for EC2, Synvya-specific environment configs, deploy scripts, CI/CD workflows for ECR

### 4. Keep `synvya` up to date with `main`
After syncing `main` with upstream:
```bash
git checkout synvya
git merge main
# resolve any conflicts
git push origin synvya
```

## What Goes Where

| Content | Branch | Contributable? |
|---|---|---|
| AWS KMS encryption provider (`AwsKmsProvider`) | `feat/aws-kms` → upstream PR → `main` | Yes |
| AWS SES email provider (`AwsSesEmailProvider`) | `feat/aws-ses` → upstream PR → `main` | Yes |
| Provider selection via env var (`KMS_PROVIDER`, `EMAIL_PROVIDER`) | Same as above (part of the provider PRs) | Yes |
| Cargo feature flags (`aws`, `gcp`) | Same as above | Yes |
| Docker Compose for EC2 deployment | `synvya/*` → `synvya` branch | No |
| GitHub Actions for ECR push | `synvya/*` → `synvya` branch | No |
| Synvya OAuth application seed data | `synvya/*` → `synvya` branch | No |
| Synvya signing policy configuration | `synvya/*` → `synvya` branch | No |
| ALB health check customization | `synvya/*` → `synvya` branch | No |
| Bug fixes in existing Keycast code | `fix/*` → upstream PR → `main` | Yes |

## Workflow Examples

### Contributing the AWS KMS provider

```bash
# Start from clean main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feat/aws-kms

# Develop, test, commit
# ... (no Synvya-specific code)

# Push to our fork
git push origin feat/aws-kms

# Open PR on GitHub: Synvya/keycast:feat/aws-kms → divinevideo/keycast:main
# After upstream merges:

git checkout main
git fetch upstream
git merge upstream/main
git push origin main

# Bring it into synvya branch
git checkout synvya
git merge main
git push origin synvya
```

### Adding a Synvya deploy script

```bash
# Start from synvya branch
git checkout synvya
git pull origin synvya

# Create working branch
git checkout -b synvya/deploy-scripts

# Develop, commit
git push origin synvya/deploy-scripts

# Open PR on GitHub: synvya/deploy-scripts → synvya branch (on Synvya/keycast)
# Merge into synvya
```

### Syncing with upstream

```bash
git fetch upstream
git checkout main
git merge upstream/main
git push origin main

git checkout synvya
git merge main
# Resolve conflicts if any
git push origin synvya
```

## Initial Setup Checklist

- [x] Fork `divinevideo/keycast` to `Synvya/keycast`
- [x] Add `upstream` remote
- [ ] Create `synvya` branch from `main`
- [ ] Open issue on `divinevideo/keycast` proposing AWS KMS and SES providers
- [ ] Implement `feat/aws-kms` (branch from `main`)
- [ ] Implement `feat/aws-ses` (branch from `main`)
- [ ] Create Synvya deploy configuration (branch from `synvya`)
- [ ] Deploy to EC2
