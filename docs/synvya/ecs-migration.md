# ECS Migration Path

Current deployment: EC2 + Docker Compose (single instance per environment).

When scaling demands outgrow the EC2 approach, migrate to AWS ECS (Fargate).

## When to migrate

- Multiple concurrent users causing resource contention
- Need for auto-scaling (traffic spikes around meal times)
- Requiring zero-downtime rolling deploys
- Running multiple services that need independent scaling

## What changes

| Component | Current (EC2) | Future (ECS) |
|---|---|---|
| Keycast | Docker Compose on EC2 | ECS Fargate service |
| Event Processor | Docker Compose on EC2 | Separate ECS Fargate service |
| MCP Server | Docker Compose on EC2 | Separate ECS Fargate service |
| Client | Docker Compose on EC2 | Separate ECS Fargate service |
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
