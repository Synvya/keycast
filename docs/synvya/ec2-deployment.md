# Keycast EC2 Deployment — v2.0

Deploy Keycast on EC2 using Docker Compose, replacing the current Google Cloud Run deployment. This is Synvya-specific infrastructure.

This document describes Keycast only. The Server is a separate service deployed to ECS/Fargate and exposed on `server.*`.

## 1. Scope

This document covers:

- Keycast deployment on EC2
- PostgreSQL and Redis for Keycast
- ALB and DNS for `auth.staging.synvya.com` and `auth.synvya.com`
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

### 3.2 Non-Goals

- does not co-host the Server
- does not front the Server behind `auth.*`
- does not move Keycast to ECS yet

## 4. Environments

| | Staging | Production |
|---|---|---|
| Domain | `auth.staging.synvya.com` | `auth.synvya.com` |
| Runtime | EC2 + Docker Compose | EC2 + Docker Compose |
| PostgreSQL | containerized in v1 | containerized in v1 |
| Redis | containerized in v1 | containerized in v1 |
| Secrets path | `synvya/staging/keycast/*` | `synvya/prod/keycast/*` |

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
ALB
   |
   v
auth.staging.synvya.com / auth.synvya.com
   |
   v
EC2 instance
  - keycast
  - postgres
  - redis
  - migration job
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
- `synvya/prod/keycast/*`

Examples:

- `server-nsec`
- `postgres-password`

Do not load Server-specific secrets in the Keycast deployment.

## 10. CI/CD

Keycast CI/CD remains Keycast-specific:

1. build and test Keycast
2. deploy Keycast to the matching EC2 environment
3. verify Keycast health

This workflow should not build or deploy the Server.

## 11. Monitoring

Monitor:

- Keycast health
- auth latency
- signing latency
- EC2 system metrics
- Postgres and Redis health

Do not mix Server alarms into this deployment document.

## 12. Relationship to ECS

- Keycast remains on EC2 + Docker Compose for now
- the Server is already targeted at ECS/Fargate + ECR
- if Keycast later moves to ECS, that should be documented separately
