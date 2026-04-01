# EC2 Deployment — v1.0

Deploy Keycast on an EC2 instance using Docker Compose, replacing the current Google Cloud Run deployment. This is Synvya-specific infrastructure — not contributed upstream.

**Architecture context**: See [Synvya Architecture](architecture-context.md) for how Keycast fits into the Synvya platform. The Event Processor shares this EC2 instance.

## 1. Problem Statement

Keycast currently runs on Google Cloud Run (`openvine-co` project) with:
- Cloud SQL PostgreSQL (`keycast-db-plus`)
- GCP Memorystore Redis
- GCP KMS for encryption
- SendGrid for email
- Cloud Build CI/CD pipeline (`cloudbuild.yaml`)
- 3 minimum instances at 4 CPUs each for NIP-46 signer uptime

Synvya's infrastructure is on AWS. Running Keycast on GCP means:
- Two cloud providers to manage (billing, IAM, networking, monitoring)
- Cross-cloud latency between Keycast (GCP) and the Event Processor (AWS EC2)
- Separate secret management (GCP Secret Manager + AWS Secrets Manager)

Moving Keycast to EC2 co-locates it with the Event Processor on the same instance, eliminating cross-cloud latency for NIP-46 RPC calls (~50ms HTTP on localhost vs ~100ms+ cross-cloud).

## 2. Goals and Non-Goals

### 2.1 Goals

- Deploy Keycast + Event Processor on EC2 instances using Docker Compose
- Maintain two environments: **staging** (`auth.staging.synvya.com`) and **production** (`auth.synvya.com`) with fully isolated data
- Use RDS PostgreSQL instead of Cloud SQL
- Use ElastiCache Redis instead of GCP Memorystore
- Use AWS KMS instead of GCP KMS (see [AWS KMS Provider spec](aws-kms-provider.md))
- Use AWS SES instead of SendGrid (see [AWS SES Provider spec](aws-ses-provider.md))
- Route traffic via ALB with path-based routing
- Automate deployment via GitHub Actions
- Store secrets in AWS Secrets Manager or SSM Parameter Store

### 2.2 Non-Goals

- Does NOT set up a multi-instance cluster — single EC2 instance per environment for v1
- Does NOT use ECS, EKS, or Fargate — Docker Compose on EC2 is simpler for a single instance
- Does NOT modify the Keycast application code — only deployment configuration
- Does NOT remove the Cloud Run deployment — that remains in upstream's `cloudbuild.yaml`

## 3. Environments

Two fully isolated environments. Same Docker Compose file, different `.env` and infrastructure.

| | Staging | Production |
|---|---|---|
| Domain | `auth.staging.synvya.com` | `auth.synvya.com` |
| EC2 | `t3.xlarge` for first build, then `t3.medium` | `t3.xlarge` for first build, then `t3.medium` |
| PostgreSQL | Containerized (same instance) | Containerized v1, RDS v2 |
| Redis | Containerized (same instance) | Containerized v1, ElastiCache v2 |
| KMS | Shared AWS KMS key | Shared AWS KMS key |
| SES | SES sandbox (verified recipients only) | SES production access |
| DynamoDB | `synvya-staging-reservation-state`, `synvya-staging-restaurant-config` | `synvya-reservation-state`, `synvya-restaurant-config` |
| Keycast nsec | Separate server nsec | Separate server nsec |
| Deploy trigger | Push to `synvya-staging` branch | Push to `synvya` branch |
| Secrets path | `synvya/staging/keycast/*`, `synvya/staging/event-processor/*` | `synvya/prod/keycast/*`, `synvya/prod/event-processor/*` |

Staging uses completely separate data — its own PostgreSQL database, DynamoDB tables, Keycast server identity, and Nostr keypairs. No staging action can affect production data.

**Relationship to other services**: All Synvya services follow the same `*.staging.synvya.com` pattern:

| Service | Staging | Production |
|---|---|---|
| Keycast + Event Processor (EC2) | `auth.staging.synvya.com` | `auth.synvya.com` |
| MCP Server (Vercel) | `mcp.staging.synvya.com` | `mcp.synvya.com` |
| Client App (S3 + CloudFront) | `account.staging.synvya.com` | `account.synvya.com` |

Each staging service points to the staging versions of its dependencies (e.g., staging MCP server calls staging Event Processor, staging client authenticates against staging Keycast).

## 4. Target Architecture

```
                         ┌──────────────────────────────────────┐
                         │  ALB (auth.synvya.com or             │
                         │       auth.staging.synvya.com)       │
                         │                                      │
                         │  /api/auth/*  ──► :3000 (Keycast)    │
                         │  /api/nostr   ──► :3000 (Keycast)    │
                         │  /api/events/* ──► :4000 (Event Proc) │
                         │  /health      ──► :3000 (Keycast)    │
                         │  /*           ──► :3000 (Keycast)    │
                         └──────────┬───────────────────────────┘
                                    │
┌───────────────────────────────────┼───────────────────────────────────┐
│  EC2 Instance                                                          │
│                                                                        │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │  Docker Compose                                                  │  │
│  │                                                                  │  │
│  │  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │  │
│  │  │  PostgreSQL   │  │  Redis            │  │  Keycast (:3000) │  │  │
│  │  │  (:5432)      │  │  (:6379)          │  │  API + Signer    │  │  │
│  │  │  Volume:      │  │                   │  │  + SvelteKit     │  │  │
│  │  │  pgdata       │  │                   │  │                  │  │  │
│  │  └──────────────┘  └──────────────────┘  └──────────────────┘  │  │
│  │                                                                  │  │
│  │  ┌──────────────────┐  ┌─────────────────────────────────────┐  │  │
│  │  │  DB Migrations    │  │  Event Processor (:4000)            │  │  │
│  │  │  (run on deploy)  │  │  (see event-processor spec)         │  │  │
│  │  └──────────────────┘  └─────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  AWS KMS ◄── encrypt/decrypt (via IAM role)                           │
│  AWS SES ◄── send email (via IAM role)                                │
│  AWS Secrets Manager ◄── secrets at startup                           │
└───────────────────────────────────────────────────────────────────────┘
```

### 4.1 v1: Containerized PostgreSQL + Redis

For v1, PostgreSQL and Redis run as Docker containers on the same EC2 instance. This simplifies setup and keeps costs low. Data is persisted via Docker volumes.

### 4.2 v2: Managed Services

Future migration to RDS PostgreSQL and ElastiCache Redis for automated backups, failover, and patching. The application code doesn't change — only the `DATABASE_URL` and `REDIS_URL` env vars.

## 5. Docker Compose Configuration

The existing `docker-compose.yml` in the Keycast repo is the starting point. Synvya's version adds the Event Processor and replaces GCP-specific config with AWS equivalents.

### 5.1 Synvya Docker Compose

File: `docker-compose.synvya.yml` (on the `synvya` branch)

```yaml
services:
  postgres:
    image: postgres:16
    container_name: keycast-postgres
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?error}
      POSTGRES_DB: keycast
      POSTGRES_USER: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    networks:
      - synvya

  redis:
    image: redis:7-alpine
    container_name: keycast-redis
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped
    networks:
      - synvya

  migrate:
    build:
      context: ./keycast/database
      dockerfile: Dockerfile
    container_name: keycast-migrate
    environment:
      DATABASE_URL: postgres://postgres:${POSTGRES_PASSWORD:?error}@postgres:5432/keycast
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - synvya
    restart: "no"

  keycast:
    container_name: keycast
    build:
      context: ./keycast
      args:
        - CARGO_FEATURES=aws
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgres://postgres:${POSTGRES_PASSWORD:?error}@postgres:5432/keycast
      REDIS_URL: redis://redis:6379
      SERVER_NSEC: ${SERVER_NSEC:?error}
      BUNKER_RELAYS: ${BUNKER_RELAYS:?error}
      ALLOWED_ORIGINS: https://auth.synvya.com
      PORT: 3000
      NODE_ENV: production
      RUST_LOG: ${RUST_LOG:-info}
      # AWS KMS
      KMS_PROVIDER: aws
      AWS_KMS_KEY_ID: ${AWS_KMS_KEY_ID:?error}
      AWS_REGION: ${AWS_REGION:-us-east-1}
      # AWS SES
      EMAIL_PROVIDER: ses
      FROM_EMAIL: ${FROM_EMAIL:-noreply@synvya.com}
      FROM_NAME: ${FROM_NAME:-Synvya}
      BASE_URL: https://auth.synvya.com
      APP_URL: https://auth.synvya.com
      # Frontend
      VITE_DOMAIN: https://auth.synvya.com
      VITE_ALLOWED_PUBKEYS: ${VITE_ALLOWED_PUBKEYS:-}
      VITE_NDK_EXPLICIT_RELAYS: ${VITE_NDK_EXPLICIT_RELAYS:-}
      VITE_NDK_BUNKER_RELAYS: ${VITE_NDK_BUNKER_RELAYS:-}
      # Performance
      SQLX_POOL_SIZE: ${SQLX_POOL_SIZE:-10}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      migrate:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s
    restart: unless-stopped
    networks:
      - synvya

  event-processor:
    container_name: event-processor
    build:
      context: ./event-processor
    ports:
      - "4000:4000"
    environment:
      PORT: 4000
      KEYCAST_URL: http://keycast:3000
      KEYCAST_SERVICE_TOKEN: ${EP_SERVICE_TOKEN:?error}
      NOSTR_RELAYS: ${NOSTR_RELAYS:?error}
      DYNAMODB_RESERVATION_TABLE: synvya-reservation-state
      DYNAMODB_CONFIG_TABLE: synvya-restaurant-config
      AWS_REGION: ${AWS_REGION:-us-east-1}
      LOG_LEVEL: ${LOG_LEVEL:-info}
    depends_on:
      keycast:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4000/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    networks:
      - synvya

volumes:
  postgres_data:

networks:
  synvya:
```

### 5.2 Dockerfile Change for Feature Flags

The Keycast Dockerfile needs a build arg for Cargo features:

```dockerfile
# In the rust-builder stage
ARG CARGO_FEATURES=""
RUN if [ -n "$CARGO_FEATURES" ]; then \
      cargo build --release --bin keycast --features "$CARGO_FEATURES"; \
    else \
      cargo build --release --bin keycast; \
    fi
```

This allows `docker compose build --build-arg CARGO_FEATURES=aws` to enable the AWS providers without affecting the upstream Dockerfile default.

## 6. EC2 Instance Setup

### 6.1 Instance Specification

| Property | Staging | Production |
|---|---|---|
| Instance type | `t3.xlarge` for first build; downsize to `t3.medium` after | `t3.xlarge` for first build; downsize to `t3.medium` after |
| AMI | Amazon Linux 2023 | Amazon Linux 2023 |
| Storage | 20 GB gp3 EBS | 30 GB gp3 EBS |
| Security group | Inbound: 80/443 from ALB. SSH (22) from admin IP. Port 3000 open during initial testing (before ALB). | Same |
| IAM role | `synvya-ec2-staging` | `synvya-ec2-prod` |
| Elastic IP | Required — assign before configuring GitHub Actions secrets | Required |

> **Instance sizing**: Building the Rust + AWS SDK Docker image requires at least a t3.xlarge (4 vCPU, 16 GB RAM) for the first build. After that, Docker layer caching makes subsequent builds much faster and the instance can be downsized to a t3.medium for normal operation.

> **Port 3000**: Open port 3000 in the security group for direct access during initial testing (before ALB is set up). Once ALB is configured, restrict port 3000 to the ALB security group only.

> **Elastic IP**: Assign an Elastic IP to the instance so the public IP doesn't change on stop/start. This matters because the IP is stored in GitHub Actions secrets (`EC2_STAGING_HOST`/`EC2_PROD_HOST`) — without it, every instance restart requires updating those secrets.

Both IAM roles have the same permission structure (see below), scoped to their respective DynamoDB tables and secrets paths.

### 6.2 IAM Role Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KMS",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": "arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
    },
    {
      "Sid": "SES",
      "Effect": "Allow",
      "Action": "ses:SendEmail",
      "Resource": "arn:aws:ses:us-east-1:ACCOUNT_ID:identity/synvya.com"
    },
    {
      "Sid": "SecretsManager",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:synvya/<ENV>/*"
    },
    {
      "Sid": "DynamoDB",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/<PREFIX>-reservation-state",
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/<PREFIX>-reservation-state/index/*",
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/<PREFIX>-restaurant-config"
      ]
    }
  ]
}
```

### 6.3 Instance Bootstrap

One-time setup on the EC2 instance.

> **Docker on Amazon Linux 2023**: The default `dnf install docker` package does not include the buildx or compose plugins. Docker CE repos (CentOS/Fedora) don't work with Amazon Linux 2023's version string. Install docker via dnf, then manually install both plugins.

```bash
# Install Docker (base package from Amazon Linux 2023)
sudo dnf update -y
sudo dnf install -y docker
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker ec2-user

# Install buildx plugin manually
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL https://github.com/docker/buildx/releases/download/v0.14.1/buildx-v0.14.1.linux-amd64 \
  -o /usr/local/lib/docker/cli-plugins/docker-buildx
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx

# Install Docker Compose plugin manually
sudo curl -SL https://github.com/docker/compose/releases/download/v2.29.1/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Add swap space (2 GB) — safety net even on larger instances
# Note: swap does not persist across reboots; re-run this after each reboot if needed
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile

# Clone the repos
mkdir -p /opt/synvya
cd /opt/synvya
git clone https://github.com/Synvya/keycast.git
git clone https://github.com/Synvya/event-processor.git  # optional for initial Keycast testing
cd keycast && git checkout synvya-staging
```

> **Re-login required**: After `usermod -aG docker ec2-user`, log out and back in for the group change to take effect before running any `docker` commands.

## 7. ALB Configuration

### 7.1 Target Groups

| Target Group | Port | Health Check |
|---|---|---|
| `synvya-keycast` | 3000 | `GET /health` — healthy threshold: 2, unhealthy: 3, interval: 30s |
| `synvya-event-processor` | 4000 | `GET /health` — same thresholds |

### 7.2 Listener Rules (HTTPS :443)

Priority order:

| Priority | Condition | Target Group |
|---|---|---|
| 1 | Path is `/api/events/*` | `synvya-event-processor` |
| 2 | Path is `/api/auth/*` | `synvya-keycast` |
| 3 | Path is `/api/nostr` | `synvya-keycast` |
| 4 | Path is `/api/oauth/*` | `synvya-keycast` |
| 5 | Path is `/api/user/*` | `synvya-keycast` |
| 6 | Path is `/api/teams/*` | `synvya-keycast` |
| Default | All other paths | `synvya-keycast` |

### 7.3 SSL Certificates

| Environment | Certificate | Covers |
|---|---|---|
| Staging | `*.staging.synvya.com` (wildcard) | All staging services |
| Production | `auth.synvya.com` | Keycast + Event Processor |

Both validated via DNS in Route 53. The wildcard staging certificate covers `auth.staging.synvya.com`, `mcp.staging.synvya.com`, and `account.staging.synvya.com` with a single cert.

## 8. Secrets Management

Secrets are stored in AWS Secrets Manager and loaded into environment variables at deploy time. Each environment has its own secret path prefix.

**Production** (`synvya/prod/`):

| Secret Path | Value | Used By |
|---|---|---|
| `synvya/prod/keycast/server-nsec` | Keycast server Nostr secret key | Keycast (`SERVER_NSEC`) |
| `synvya/prod/keycast/postgres-password` | PostgreSQL password | Keycast + Postgres (`POSTGRES_PASSWORD`) |
| `synvya/prod/event-processor/service-token` | EP's Keycast service token | Event Processor (`EP_SERVICE_TOKEN`) |
| `synvya/prod/event-processor/api-key` | MCP→EP API key | Event Processor + MCP Server |

**Staging** (`synvya/staging/`): Same structure, different values. Staging uses a separate server nsec so staging events don't pollute the production Nostr identity.

> **Postgres password**: Must be **alphanumeric only** (no special characters). The password is embedded in the `DATABASE_URL` connection string (`postgres://postgres:<PASSWORD>@postgres:5432/keycast`), and characters like `@`, `/`, `#`, or `$` break URL parsing. If you need to change the postgres password after first initialization, you must wipe the Docker volume: `docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env down -v` (this deletes all data — only do this on a fresh instance or after backing up).

### 8.1 Loading Secrets at Deploy Time

A deploy script fetches secrets from Secrets Manager and writes them to a `.env` file that Docker Compose reads. The script takes an environment argument:

```bash
#!/bin/bash
# scripts/load-secrets.sh
set -euo pipefail

ENV=${1:?Usage: load-secrets.sh <staging|prod>}
REGION=${AWS_REGION:-us-east-1}

get_secret() {
    aws secretsmanager get-secret-value \
        --secret-id "$1" \
        --query 'SecretString' \
        --output text \
        --region "$REGION"
}

if [ "$ENV" = "staging" ]; then
    DOMAIN=auth.staging.synvya.com
    DYNAMO_PREFIX=synvya-staging
else
    DOMAIN=auth.synvya.com
    DYNAMO_PREFIX=synvya
fi

cat > /opt/synvya/.env <<EOF
# IMPORTANT: postgres password must be alphanumeric only (no @, /, #, $ etc.)
# Special characters break URL parsing in DATABASE_URL.
POSTGRES_PASSWORD=$(get_secret synvya/$ENV/keycast/postgres-password)
SERVER_NSEC=$(get_secret synvya/$ENV/keycast/server-nsec)
EP_SERVICE_TOKEN=$(get_secret synvya/$ENV/event-processor/service-token)
AWS_KMS_KEY_ID=alias/keycast-master-key
AWS_REGION=$REGION
BUNKER_RELAYS=wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social
NOSTR_RELAYS=wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social
ALLOWED_ORIGINS=https://$DOMAIN
BASE_URL=https://$DOMAIN
APP_URL=https://$DOMAIN
VITE_DOMAIN=https://$DOMAIN
FROM_EMAIL=noreply@synvya.com
FROM_NAME=Synvya
DYNAMODB_RESERVATION_TABLE=${DYNAMO_PREFIX}-reservation-state
DYNAMODB_CONFIG_TABLE=${DYNAMO_PREFIX}-restaurant-config
VITE_ALLOWED_PUBKEYS=${VITE_ALLOWED_PUBKEYS:-}
EOF

chmod 600 /opt/synvya/.env
```

## 9. CI/CD — GitHub Actions

### 9.1 Deployment Workflows

Two workflows, one per environment:

**Staging** — `.github/workflows/deploy-staging.yml`:

```yaml
name: Deploy to Staging

on:
  push:
    branches: [synvya-staging]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy via SSH
        uses: appleboy/ssh-action@v1
        with:
          host: ${{ secrets.EC2_STAGING_HOST }}
          username: ec2-user
          key: ${{ secrets.EC2_STAGING_SSH_KEY }}
          script: |
            cd /opt/synvya
            cd keycast && git pull origin synvya-staging && cd ..
            cd event-processor && git pull origin main && cd ..
            bash keycast/scripts/load-secrets.sh staging
            # --env-file is required: Docker Compose resolves .env relative to the
            # compose file location, not the current working directory.
            docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env build
            docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env up -d
            sleep 10
            curl -f http://localhost:3000/health || exit 1
            # Event processor is optional; skip health check if not running
            curl -f http://localhost:4000/health || echo "event-processor not running (optional)"
```

> **GitHub secrets**: `EC2_STAGING_HOST` and `EC2_STAGING_SSH_KEY` must be configured in the repo's GitHub Actions secrets **before** the first push to `synvya-staging`. The workflow runs on every push to that branch — if the secrets are missing, the job will fail immediately with "missing server host".

**Production** — `.github/workflows/deploy-prod.yml`:

```yaml
name: Deploy to Production

on:
  push:
    branches: [synvya]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy via SSH
        uses: appleboy/ssh-action@v1
        with:
          host: ${{ secrets.EC2_PROD_HOST }}
          username: ec2-user
          key: ${{ secrets.EC2_PROD_SSH_KEY }}
          script: |
            cd /opt/synvya
            cd keycast && git pull origin synvya && cd ..
            cd event-processor && git pull origin main && cd ..
            bash keycast/scripts/load-secrets.sh prod
            docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env build
            docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env up -d
            sleep 10
            curl -f http://localhost:3000/health || exit 1
            curl -f http://localhost:4000/health || exit 1
```

**Recommended workflow**: Push to `synvya-staging` first. Verify in staging. Then merge `synvya-staging` → `synvya` to deploy to production.

### 9.2 GitHub Secrets

| Secret | Purpose |
|---|---|
| `EC2_STAGING_HOST` | Staging EC2 public IP or hostname |
| `EC2_STAGING_SSH_KEY` | SSH private key for staging `ec2-user` |
| `EC2_PROD_HOST` | Production EC2 public IP or hostname |
| `EC2_PROD_SSH_KEY` | SSH private key for production `ec2-user` |

## 10. Monitoring

### 10.1 CloudWatch Agent

Install the CloudWatch agent on the EC2 instance to collect:

- **Docker container logs**: JSON logs from Keycast and Event Processor
- **System metrics**: CPU, memory, disk, network
- **Custom metrics**: From Keycast's `/health` endpoint

### 10.2 Health Check Alarms

| Alarm | Condition | Action |
|---|---|---|
| Keycast unhealthy | ALB target group unhealthy > 2 min | SNS notification |
| Event Processor unhealthy | ALB target group unhealthy > 2 min | SNS notification |
| Disk usage > 80% | CloudWatch metric | SNS notification |
| CPU > 80% sustained 10 min | CloudWatch metric | SNS notification |

### 10.3 Log Groups

| Log Group | Source |
|---|---|
| `/synvya/keycast` | Keycast container stdout/stderr |
| `/synvya/event-processor` | Event Processor container stdout/stderr |
| `/synvya/postgres` | PostgreSQL container logs |

## 11. Backup Strategy

### 11.1 PostgreSQL Backups

Daily automated backups of the PostgreSQL data volume:

```bash
#!/bin/bash
# scripts/backup-postgres.sh (run via cron)
BACKUP_DIR=/opt/synvya/backups
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

docker exec keycast-postgres pg_dump -U postgres keycast | gzip > "$BACKUP_DIR/keycast_$TIMESTAMP.sql.gz"

# Upload to S3
aws s3 cp "$BACKUP_DIR/keycast_$TIMESTAMP.sql.gz" s3://synvya-backups/keycast/

# Retain 7 days locally
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete
```

Cron entry:
```
0 3 * * * /opt/synvya/keycast/scripts/backup-postgres.sh
```

### 11.2 S3 Backup Retention

S3 lifecycle policy on `synvya-backups/keycast/`:
- Transition to Glacier after 30 days
- Delete after 90 days

## 12. Rollback

Docker Compose supports immediate rollback:

```bash
# If a deployment fails, roll back to previous image
docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env down
git -C keycast checkout HEAD~1
docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env up -d --build
```

PostgreSQL data persists across deployments (Docker volume). Database migrations are idempotent (0002+), so rolling back the application doesn't require rolling back migrations.

## 12.1 Files Changed

All on the `synvya` branch (Synvya-specific, not upstream):

| File | Description |
|---|---|
| `docker-compose.synvya.yml` | Synvya production Docker Compose with Keycast + Event Processor |
| `scripts/load-secrets.sh` | Fetch secrets from AWS Secrets Manager into `.env` |
| `scripts/backup-postgres.sh` | Daily PostgreSQL backup to S3 |
| `.github/workflows/deploy.yml` | GitHub Actions deploy-to-EC2 workflow |
| `Dockerfile` (modification) | Add `CARGO_FEATURES` build arg for AWS feature flag |

## 13. Starting Without the Event Processor

Keycast can run without the Event Processor for initial testing or if the event-processor repo has not been cloned yet:

```bash
# Start only Keycast and its dependencies
docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env \
  up -d postgres redis migrate keycast
```

The Event Processor requires its own repo cloned at `/opt/synvya/event-processor`. Start the full stack only after that repo is present:

```bash
docker compose -f keycast/docker-compose.synvya.yml --env-file /opt/synvya/.env up -d
```

## 14. Known Issues and Lessons Learned

### 14.1 Dockerfile Runtime Base Image

The Dockerfile runtime stage must use `debian:trixie-slim` (not `debian:bookworm-slim`) to match the glibc version bundled with `rust:1.93-slim` (the builder stage). Using `bookworm-slim` causes a glibc version mismatch at runtime: the binary segfaults or fails to start. Fixed in commit `432cf24`.

### 14.2 Docker Compose `--env-file` Resolution

Docker Compose resolves `.env` relative to the **compose file location**, not the current working directory. When running compose commands from `/opt/synvya` with `-f keycast/docker-compose.synvya.yml`, Docker looks for `.env` in `keycast/` — not in `/opt/synvya/`. Always pass `--env-file /opt/synvya/.env` explicitly on every compose command.

### 14.3 Amazon Linux 2023 Docker Installation

The `dnf install docker` package on Amazon Linux 2023 does not include buildx or the compose plugin. Docker CE repos (CentOS/Fedora) are incompatible with Amazon Linux 2023's version string. Install the base `docker` package via dnf, then download buildx and docker-compose binaries manually into `/usr/local/lib/docker/cli-plugins/` (see Section 6.3).

### 14.4 EC2 Instance Sizing for First Build

A t3.small (2 GB RAM) is insufficient to build the Rust + AWS SDK Docker image. The build OOMs and fails silently or hangs. Use a t3.xlarge (16 GB RAM) for the first build. After that, Docker layer caching means incremental builds use far less memory and the instance can be downsized to t3.medium.

### 14.5 Swap Space

Add 2 GB of swap even on larger instances as a safety net for memory spikes during builds:

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
```

Swap does not persist across reboots. Re-run after each reboot, or add it to `/etc/fstab` for persistence.

### 14.6 Postgres Password Must Be Alphanumeric

The postgres password gets embedded in the `DATABASE_URL` connection string. Special characters (`@`, `/`, `#`, `$`, etc.) break URL parsing and cause connection failures. Use alphanumeric passwords only. If the password is changed after first initialization, the postgres Docker volume must be wiped (`docker compose ... down -v`) since Postgres only sets the password on first init.

## 15. Migration from Cloud Run

### 14.1 Prerequisites

Before switching DNS:

- [ ] EC2 instance provisioned with IAM role
- [ ] Docker + Docker Compose installed
- [ ] ALB configured with target groups and listener rules
- [ ] ACM certificate for `auth.synvya.com` issued and validated
- [ ] AWS KMS key created (see [AWS KMS Provider spec](aws-kms-provider.md))
- [ ] SES domain verified and production access granted (see [AWS SES Provider spec](aws-ses-provider.md))
- [ ] Secrets created in AWS Secrets Manager
- [ ] GitHub Actions secrets configured
- [ ] PostgreSQL backup cron configured

### 14.2 Data Migration

1. Export PostgreSQL data from Cloud SQL:
   ```bash
   gcloud sql export sql keycast-db-plus gs://BUCKET/keycast-export.sql --database=keycast
   ```
2. Import into EC2 PostgreSQL:
   ```bash
   gsutil cp gs://BUCKET/keycast-export.sql .
   docker exec -i keycast-postgres psql -U postgres keycast < keycast-export.sql
   ```
3. Re-encrypt all stored keys from GCP KMS to AWS KMS (see data migration section in [AWS KMS Provider spec](aws-kms-provider.md))

### 14.3 DNS Cutover

1. Deploy to EC2, verify health checks pass
2. Test with a custom host header or `/etc/hosts` entry pointing `auth.synvya.com` to the ALB
3. Update Route 53 A record for `auth.synvya.com` to point to the ALB
4. Monitor for errors in CloudWatch logs
5. Keep Cloud Run deployment running for 48 hours as fallback
