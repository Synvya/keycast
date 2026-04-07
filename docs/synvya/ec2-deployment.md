# Keycast EC2 Deployment — v2.1

Deploy Keycast on EC2 using Docker Compose. This is Synvya-specific infrastructure.

This document describes Keycast only. The Server is a separate service deployed to ECS/Fargate and exposed on `server.*`.

## 1. Scope

This document covers:

- Keycast deployment on EC2
- PostgreSQL and Redis for Keycast
- ALB, WAF, and DNS for `auth.staging.synvya.com` and `auth.synvya.com`
- GitHub Actions deployment of Keycast-specific changes

This document does not cover:

- Server deployment
- reservation or catalog APIs
- public Nostr discovery caching

## 2. Problem Statement

Keycast currently runs on Google Cloud Run with GCP-managed dependencies. Synvya infrastructure is on AWS, so Keycast needs an AWS-native deployment with:

- AWS KMS instead of GCP KMS
- AWS SES instead of SendGrid
- AWS-hosted runtime and secret management

EC2 + Docker Compose remains the chosen Keycast deployment target for now.

## 3. Goals and Non-Goals

### 3.1 Goals

- deploy Keycast on EC2 using Docker Compose
- maintain staging and production isolation
- expose Keycast on `auth.staging.synvya.com` and `auth.synvya.com`
- use AWS KMS and AWS SES
- protect email-triggering endpoints from bot abuse via AWS WAF

### 3.2 Non-Goals

- does not co-host the Server
- does not front the Server behind `auth.*`
- does not move Keycast to ECS yet

## 4. Environments

| | Staging | Production |
|---|---|---|
| Domain | `auth.staging.synvya.com` | `auth.synvya.com` |
| Runtime | EC2 + Docker Compose | EC2 + Docker Compose |
| PostgreSQL | containerized | containerized |
| Redis | containerized | containerized |
| Secrets path | `synvya/staging/keycast/*` | `synvya/production/keycast/*` |
| KMS key alias | `alias/keycast-master-key` | `alias/synvya-production-keycast-masterkey` |
| WAF Web ACL | `synvya-staging-keycast-waf` | `synvya-production-keycast-waf` |

## 5. Service Boundary

| Host | Service | Purpose |
|---|---|---|
| `auth.staging.synvya.com` | Keycast | staging auth + signing RPC |
| `auth.synvya.com` | Keycast | production auth + signing RPC |
| `server.staging.synvya.com` | Server | staging business API |
| `server.synvya.com` | Server | production business API |

Keycast owns:

- `/api/auth/*`
- `/api/nostr`
- OAuth and user-facing Keycast routes
- its own `/health`

Keycast does not own:

- `/api/reservations/*`
- `/api/catalog/*`

## 6. Target Architecture

```text
Internet
   |
   v
AWS WAF (rate limiting + IP reputation)
   |
   v
ALB (HTTPS 443, *.synvya.com cert)
   |
   v
auth.staging.synvya.com / auth.synvya.com
   |
   v
EC2 instance
  - keycast (port 3000)
  - postgres
  - redis
  - migration job (runs once on deploy)
```

The Server is a separate service on ECS/Fargate and is not part of this stack.

## 7. Docker Compose

Keycast compose includes:

- `postgres`
- `redis`
- `migrate`
- `keycast`

It should not include a server or event-processor container.

## 8. ALB Configuration

### 8.1 Target Group

| Target Group | Port | Health Check |
|---|---|---|
| `synvya-keycast` | 3000 | `GET /health` |

### 8.2 Listener Rules

For the `auth.*` hosts, route these paths to Keycast:

- `/api/auth/*`
- `/api/nostr`
- `/api/oauth/*`
- `/api/user/*`
- `/api/teams/*`
- `/health`
- all Keycast UI routes

There is no `/api/events/*` routing in the Keycast stack anymore.

## 9. Secrets

Keycast secrets live under:

- `synvya/staging/keycast/*`
- `synvya/production/keycast/*`

| Secret name | Description |
|---|---|
| `privatekey` | Server Nostr secret key (hex or nsec bech32) |
| `postgres-password` | PostgreSQL password — alphanumeric only, no special characters |
| `allowed-pubkeys` | Comma-separated admin pubkeys for whitelist access |

Do not load Server-specific secrets in the Keycast deployment. IAM roles are scoped to `synvya/{env}/keycast/*` only.

## 10. WAF

Each environment has a dedicated AWS WAF Web ACL associated with its ALB.

| Web ACL | Associated ALB |
|---|---|
| `synvya-staging-keycast-waf` | `synvya-staging-keycast-alb` |
| `synvya-production-keycast-waf` | `synvya-production-keycast-alb` |

### Rules

**Rate-based rules** (10 requests per 1 minute per IP, action: Block):

| Rule | URI path | Protects |
|---|---|---|
| `rate-limit-register` | `/api/auth/register` | Verification email |
| `rate-limit-forgot-password` | `/api/auth/forgot-password` | Password reset email |
| `rate-limit-claim` | `/claim` | Account claim email |

**Managed rule groups** (always on):

- `AWSManagedRulesAmazonIpReputationList` — blocks known bot and scanner IPs

### Notes

- WAF is managed manually in the AWS console, not via CI/CD
- Default action is **Allow** — only matched rules block
- To test WAF on staging without blocking yourself, temporarily set rules to **Count** mode, verify metrics, then switch back to **Block**

## 11. CI/CD

Keycast CI/CD remains Keycast-specific:

1. build and test Keycast
2. deploy Keycast to the matching EC2 environment
3. verify Keycast health

This workflow should not build or deploy the Server.

## 12. Monitoring

Monitor:

- Keycast health
- auth latency
- signing latency
- EC2 system metrics
- Postgres and Redis health

Do not mix Server alarms into this deployment document.

## 13. Relationship to ECS

- Keycast remains on EC2 + Docker Compose for now
- the Server is already targeted at ECS/Fargate + ECR
- if Keycast later moves to ECS, that should be documented separately
