# ECS Deployment

## Strategy

Synvya services are split by operational role:

- **Keycast**: stays on EC2 + Docker Compose for now
- **Server**: deploys on ECS/Fargate + ECR from the start
- **MCP/OpenAPI** and **Client**: remain separate services on their own deployment paths

This document is a high-level note about that split.

## Current State

| Component | Deployment |
|---|---|
| Keycast | EC2 + Docker Compose |
| Server | ECS/Fargate + ECR |
| MCP/OpenAPI | separate service |
| Client | S3 + CloudFront |

## Why the Split Exists

**Keycast** benefits from a simpler long-running deployment while the hosted signer and auth stack stabilize.

**Server** is the higher-traffic business service and the right place to start with ECR + ECS, because it owns:

- 24/7 relay handling
- reservation processing
- NIP-65 routing
- public Nostr discovery ingestion and cache
- internal APIs consumed by other services

## ECS Scope for the Server

Server ECS deployment should include:

1. ECR repository for the server image
2. ECS task definitions and services for staging and production
3. ALB target groups for `server.staging.synvya.com` and `server.synvya.com`
4. task roles with DynamoDB and Secrets Manager access
5. environment-specific configuration for Keycast URLs and DynamoDB table names

## What Stays the Same

- Keycast remains exposed on `auth.*`
- the Server remains exposed on `server.*`
- AWS Secrets Manager remains the credential source
- DynamoDB remains the server-side operational store
