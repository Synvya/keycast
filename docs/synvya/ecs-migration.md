# ECS Deployment

## Strategy

Services are moving to AWS ECS (Fargate) + ECR incrementally — not all at once.

**Event Processor**: Goes directly to ECR + ECS. It was never deployed on EC2; ECS is its first production home. This gives Synvya a scalable, auto-scaling deployment for the highest-traffic service from day one.

**Keycast**: Stays on EC2 + Docker Compose for now. It has special requirements (persistent NIP-46 signer connections, low-latency relay subscriptions) that benefit from a long-running single process. Migrating to ECS Fargate is a future step when scaling demands require it.

**MCP Server, Client App**: Separate services on their own deployment paths (Vercel, S3+CloudFront).

## Current state

| Component | Deployment | Status |
|---|---|---|
| Keycast | EC2 + Docker Compose | Live on EC2 |
| Event Processor | ECR + ECS Fargate | Next phase |
| MCP Server | Vercel | Separate |
| Client App | S3 + CloudFront | Separate |
| PostgreSQL | Container on EC2 (Keycast) | Live; RDS in future |
| Redis | Container on EC2 (Keycast) | Live; ElastiCache in future |

## What changes (EC2 → ECS)

| Component | Current (EC2) | ECS |
|---|---|---|
| Keycast | Docker Compose on EC2 | ECS Fargate service (future) |
| Event Processor | — | ECS Fargate service (next phase) |
| PostgreSQL | Container on EC2 | Amazon RDS |
| Redis | Container on EC2 | Amazon ElastiCache |
| Load Balancer | ALB → single EC2 | ALB → ECS service targets |
| Secrets | AWS Secrets Manager → .env file | AWS Secrets Manager → ECS task env |
| Deploy trigger | SSH + git pull + docker compose | ECR push + ECS task definition update |

## Infrastructure to create

1. **ECR repositories**: one per service (keycast, event-processor, mcp-server, client)
2. **ECS cluster**: single Fargate cluster for all services
3. **ECS task definitions**: one per service, referencing ECR images
4. **ECS services**: one per service, with desired count and scaling policies
5. **RDS instance**: PostgreSQL 16, replace containerized Postgres
6. **ElastiCache cluster**: Redis 7, replace containerized Redis
7. **Security groups**: service-to-service, service-to-RDS, service-to-ElastiCache
8. **IAM roles**: task execution role (pull from ECR, read secrets), task role (app permissions)
9. **Service discovery**: ECS service connect or Cloud Map for inter-service communication

## CI/CD changes

The `build-test-push.yaml` workflow already has gated AWS ECR+ECS steps. To activate:

Set these GitHub repository variables:
- `AWS_DEPLOY_ROLE_ARN`: IAM role for deploy (OIDC)
- `AWS_REGION`: e.g., `us-east-1`
- `AWS_ECR_REPOSITORY`: ECR repository name
- `AWS_ECS_CLUSTER`: ECS cluster name
- `AWS_ECS_SERVICE`: ECS service name
- `AWS_ECS_CONTAINER_NAME`: container name in task definition

Each service (keycast, event-processor, mcp-server, client) follows the same pattern in its own workflow.

## Migration steps

1. Create RDS and ElastiCache (can run alongside EC2 during transition)
2. Migrate database from containerized Postgres to RDS
3. Create ECR repositories and push initial images
4. Create ECS cluster, task definitions, and services
5. Set GitHub variables to activate ECS deploy path
6. Update ALB target groups from EC2 to ECS
7. Validate, then decommission EC2 instances

## What stays the same

- Docker images (same Dockerfile)
- Application code and configuration
- AWS Secrets Manager for secrets
- ALB for HTTPS termination
- OIDC federation for GitHub Actions
- The `build-test-push-synvya.yaml` can be retired once ECS is active (the upstream `build-test-push.yaml` handles it)
