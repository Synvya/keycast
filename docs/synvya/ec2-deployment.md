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

- Deploy Keycast + Event Processor on a single EC2 instance using Docker Compose
- Use RDS PostgreSQL instead of Cloud SQL
- Use ElastiCache Redis instead of GCP Memorystore
- Use AWS KMS instead of GCP KMS (see [AWS KMS Provider spec](aws-kms-provider.md))
- Use AWS SES instead of SendGrid (see [AWS SES Provider spec](aws-ses-provider.md))
- Route traffic via ALB at `auth.synvya.com` with path-based routing
- Automate deployment via GitHub Actions
- Store secrets in AWS Secrets Manager or SSM Parameter Store

### 2.2 Non-Goals

- Does NOT set up a multi-instance cluster — single EC2 instance for v1
- Does NOT use ECS, EKS, or Fargate — Docker Compose on EC2 is simpler for a single instance
- Does NOT modify the Keycast application code — only deployment configuration
- Does NOT remove the Cloud Run deployment — that remains in upstream's `cloudbuild.yaml`

## 3. Target Architecture

```
                         ┌──────────────────────────────────────┐
                         │  ALB (auth.synvya.com)               │
                         │                                      │
                         │  /api/auth/*  ──► :3000 (Keycast)    │
                         │  /api/nostr   ──► :3000 (Keycast)    │
                         │  /api/events/* ──► :4000 (Event Proc) │
                         │  /health      ──► :3000 (Keycast)    │
                         │  /*           ──► :3000 (Keycast)    │
                         └──────────┬───────────────────────────┘
                                    │
┌───────────────────────────────────┼───────────────────────────────────┐
│  EC2 Instance (t3.medium or larger)                                    │
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

┌──────────────────┐
│  RDS PostgreSQL  │  ◄── alternative to containerized Postgres (v2)
│  (future)        │
└──────────────────┘
```

### 3.1 v1: Containerized PostgreSQL + Redis

For v1, PostgreSQL and Redis run as Docker containers on the same EC2 instance. This simplifies setup and keeps costs low. Data is persisted via Docker volumes.

### 3.2 v2: Managed Services

Future migration to RDS PostgreSQL and ElastiCache Redis for automated backups, failover, and patching. The application code doesn't change — only the `DATABASE_URL` and `REDIS_URL` env vars.

## 4. Docker Compose Configuration

The existing `docker-compose.yml` in the Keycast repo is the starting point. Synvya's version adds the Event Processor and replaces GCP-specific config with AWS equivalents.

### 4.1 Synvya Docker Compose

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

### 4.2 Dockerfile Change for Feature Flags

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

## 5. EC2 Instance Setup

### 5.1 Instance Specification

| Property | Value |
|---|---|
| Instance type | `t3.medium` (2 vCPU, 4 GB RAM) — upgrade to `t3.large` if needed |
| AMI | Amazon Linux 2023 |
| Storage | 30 GB gp3 EBS (for Docker images, PostgreSQL data, logs) |
| Security group | Inbound: 80/443 from ALB only. SSH (22) from admin IP only. |
| IAM role | `synvya-ec2-keycast` with KMS, SES, Secrets Manager, DynamoDB permissions |

### 5.2 IAM Role Permissions

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
      "Resource": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:synvya/keycast/*"
    },
    {
      "Sid": "DynamoDB",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/synvya-reservation-state",
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/synvya-reservation-state/index/*",
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/synvya-restaurant-config"
      ]
    }
  ]
}
```

### 5.3 Instance Bootstrap

One-time setup on the EC2 instance:

```bash
# Install Docker + Docker Compose
sudo dnf update -y
sudo dnf install -y docker
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker ec2-user

# Install Docker Compose plugin
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Clone the repos
mkdir -p /opt/synvya
cd /opt/synvya
git clone https://github.com/Synvya/keycast.git
git clone https://github.com/Synvya/event-processor.git
cd keycast && git checkout synvya
```

## 6. ALB Configuration

### 6.1 Target Groups

| Target Group | Port | Health Check |
|---|---|---|
| `synvya-keycast` | 3000 | `GET /health` — healthy threshold: 2, unhealthy: 3, interval: 30s |
| `synvya-event-processor` | 4000 | `GET /health` — same thresholds |

### 6.2 Listener Rules (HTTPS :443)

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

### 6.3 SSL Certificate

ACM certificate for `auth.synvya.com`, attached to the ALB HTTPS listener. DNS validation via Route 53.

## 7. Secrets Management

Secrets are stored in AWS Secrets Manager and loaded into environment variables at deploy time.

| Secret Path | Value | Used By |
|---|---|---|
| `synvya/keycast/server-nsec` | Keycast server Nostr secret key | Keycast (`SERVER_NSEC`) |
| `synvya/keycast/postgres-password` | PostgreSQL password | Keycast + Postgres (`POSTGRES_PASSWORD`) |
| `synvya/event-processor/service-token` | EP's Keycast service token | Event Processor (`EP_SERVICE_TOKEN`) |
| `synvya/event-processor/api-key` | MCP→EP API key | Event Processor + MCP Server |

### 7.1 Loading Secrets at Deploy Time

A deploy script fetches secrets from Secrets Manager and writes them to a `.env` file that Docker Compose reads:

```bash
#!/bin/bash
# scripts/load-secrets.sh
set -euo pipefail

REGION=${AWS_REGION:-us-east-1}

get_secret() {
    aws secretsmanager get-secret-value \
        --secret-id "$1" \
        --query 'SecretString' \
        --output text \
        --region "$REGION"
}

cat > /opt/synvya/.env <<EOF
POSTGRES_PASSWORD=$(get_secret synvya/keycast/postgres-password)
SERVER_NSEC=$(get_secret synvya/keycast/server-nsec)
EP_SERVICE_TOKEN=$(get_secret synvya/event-processor/service-token)
AWS_KMS_KEY_ID=alias/keycast-master-key
AWS_REGION=$REGION
BUNKER_RELAYS=wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social
NOSTR_RELAYS=wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social
FROM_EMAIL=noreply@synvya.com
FROM_NAME=Synvya
VITE_ALLOWED_PUBKEYS=${VITE_ALLOWED_PUBKEYS:-}
EOF

chmod 600 /opt/synvya/.env
```

## 8. CI/CD — GitHub Actions

### 8.1 Deployment Workflow

File: `.github/workflows/deploy.yml` (on the `synvya` branch of `Synvya/keycast`)

```yaml
name: Deploy to EC2

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
          host: ${{ secrets.EC2_HOST }}
          username: ec2-user
          key: ${{ secrets.EC2_SSH_KEY }}
          script: |
            cd /opt/synvya

            # Pull latest code
            cd keycast && git pull origin synvya && cd ..
            cd event-processor && git pull origin main && cd ..

            # Load secrets
            bash keycast/scripts/load-secrets.sh

            # Build and deploy
            docker compose -f keycast/docker-compose.synvya.yml build
            docker compose -f keycast/docker-compose.synvya.yml up -d

            # Wait for health
            sleep 10
            curl -f http://localhost:3000/health || exit 1
            curl -f http://localhost:4000/health || exit 1
```

### 8.2 GitHub Secrets

| Secret | Purpose |
|---|---|
| `EC2_HOST` | EC2 public IP or hostname |
| `EC2_SSH_KEY` | SSH private key for `ec2-user` |

## 9. Monitoring

### 9.1 CloudWatch Agent

Install the CloudWatch agent on the EC2 instance to collect:

- **Docker container logs**: JSON logs from Keycast and Event Processor
- **System metrics**: CPU, memory, disk, network
- **Custom metrics**: From Keycast's `/health` endpoint

### 9.2 Health Check Alarms

| Alarm | Condition | Action |
|---|---|---|
| Keycast unhealthy | ALB target group unhealthy > 2 min | SNS notification |
| Event Processor unhealthy | ALB target group unhealthy > 2 min | SNS notification |
| Disk usage > 80% | CloudWatch metric | SNS notification |
| CPU > 80% sustained 10 min | CloudWatch metric | SNS notification |

### 9.3 Log Groups

| Log Group | Source |
|---|---|
| `/synvya/keycast` | Keycast container stdout/stderr |
| `/synvya/event-processor` | Event Processor container stdout/stderr |
| `/synvya/postgres` | PostgreSQL container logs |

## 10. Backup Strategy

### 10.1 PostgreSQL Backups

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

### 10.2 S3 Backup Retention

S3 lifecycle policy on `synvya-backups/keycast/`:
- Transition to Glacier after 30 days
- Delete after 90 days

## 11. Rollback

Docker Compose supports immediate rollback:

```bash
# If a deployment fails, roll back to previous image
docker compose -f keycast/docker-compose.synvya.yml down
git -C keycast checkout HEAD~1
docker compose -f keycast/docker-compose.synvya.yml up -d --build
```

PostgreSQL data persists across deployments (Docker volume). Database migrations are idempotent (0002+), so rolling back the application doesn't require rolling back migrations.

## 12. Files Changed

All on the `synvya` branch (Synvya-specific, not upstream):

| File | Description |
|---|---|
| `docker-compose.synvya.yml` | Synvya production Docker Compose with Keycast + Event Processor |
| `scripts/load-secrets.sh` | Fetch secrets from AWS Secrets Manager into `.env` |
| `scripts/backup-postgres.sh` | Daily PostgreSQL backup to S3 |
| `.github/workflows/deploy.yml` | GitHub Actions deploy-to-EC2 workflow |
| `Dockerfile` (modification) | Add `CARGO_FEATURES` build arg for AWS feature flag |

## 13. Migration from Cloud Run

### 13.1 Prerequisites

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

### 13.2 Data Migration

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

### 13.3 DNS Cutover

1. Deploy to EC2, verify health checks pass
2. Test with a custom host header or `/etc/hosts` entry pointing `auth.synvya.com` to the ALB
3. Update Route 53 A record for `auth.synvya.com` to point to the ALB
4. Monitor for errors in CloudWatch logs
5. Keep Cloud Run deployment running for 48 hours as fallback
