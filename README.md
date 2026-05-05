# SOAR API

A comprehensive Security Orchestration, Automation, and Response (SOAR) platform built on AWS that automates and orchestrates security operations workflows. This API integrates with leading security tools to enable rapid threat enrichment, automated incident response, and coordinated remediation across your security infrastructure.

## Overview

The SOAR API provides a centralized hub for security automation, allowing your team to:
- **Enrich** security alerts with threat intelligence from multiple sources
- **Automate** incident response with coordinated actions across security tools
- **Respond** to threats natively with integrated blocking and containment capabilities
- **Orchestrate** complex security workflows across your infrastructure

## Architecture

### High-Level Architecture

```
┌─────────────┐
│  Clients    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│  AWS API Gateway                            │
│  (HTTPS, Cognito Authorizer)               │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   AWS Lambda         │
        │   (SOAR API - Go)    │
        └──────────┬───────────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
       ▼           ▼           ▼
    ┌──────┐   ┌────────┐   ┌──────┐
    │DDB   │   │KMS/SSM │   │Cognito│
    │Cache │   │Secrets │   │Auth   │
    └──────┘   └────────┘   └──────┘
       │
   ┌───┴────────────────────────────────────┐
   │                                        │
   ▼ Enrichment Services                    ▼ Response/Action Services
   • AbuseIPDB                              • Zscaler (SSE Block)
   • Anomali                                • Azure AD (Conditional Access)
   • RecordedFuture                         • Defender (Block Indicators)
                                            • Cloudflare (WAF Block)
```

### Core Components

#### Frontend & Authentication
- **API Gateway**: HTTPS endpoint with Cognito-based authorization
- **Cognito**: OpenID Connect integration for authentication and scoped authorization
- **API Key Requirements**: Enforced on all endpoints for additional security

#### Compute & Services
- **AWS Lambda**: Serverless compute layer running the Go-based API application
  - Request handling through Gin-gonic web framework
  - Auto-scaling and high availability
  - JSON-based structured logging

#### Data Layer
- **DynamoDB**: Persistent storage for IOC (Indicators of Compromise) cache
  - Reduces API call overhead to external threat intelligence services
  - TTL-based expiration for freshness management
- **KMS**: Encryption key management for sensitive API credentials
- **Systems Manager (SSM)**: Secure credential storage and retrieval

## API Endpoints

All endpoints require:
- Valid Cognito authentication token
- API key in request headers
- HTTPS connection

### Enrichment Routes (`/api/enrich/*`)

Data enrichment endpoints that provide threat intelligence for investigation and decision-making.

#### `POST /api/enrich/ipabusedb`
Check IP reputation against AbuseIPDB database with local caching.
- **Purpose**: Identify malicious, VPN, or proxy IP addresses
- **Response**: Confidence level, country, report count, TOR status
- **Caching**: Returns cached results when available

#### `POST /api/enrich/anomali`
Query Anomali threat intelligence platform for IOC data.
- **Purpose**: Identify known malicious indicators
- **Response**: Threat names, threat types, and confidence scores

#### `POST /api/enrich/recordedfuture`
Enrichment via RecordedFuture threat intelligence feed.
- **Purpose**: Cross-reference against extensive threat databases
- **Response**: Threat assessment and intelligence metadata

### Response Routes (`/api/soar/*`)

Automated response endpoints that execute containment and remediation actions.

#### `POST /api/soar/sse/zscaler`
Block traffic through Zscaler Security Service Edge.
- **Action**: Creates URL blocking rules in Zscaler
- **Use Case**: Prevent user access to known malicious domains

#### `POST /api/soar/azuread/ca`
Trigger Azure AD Conditional Access policies.
- **Action**: Block authentication to risky user accounts
- **Use Case**: Deny access, or apply device compliance checks

#### `POST /api/soar/datp/blockioc`
Submit IOCs to Microsoft Defender for Endpoint.
- **Action**: Add threats to Defender's detection rules
- **Use Case**: Block detection and automated response at endpoint level

#### `POST /api/soar/waf/blockip`
Create firewall rules in Cloudflare WAF.
- **Action**: IP-based rate limiting and blocking
- **Use Case**: Mitigate DDoS and brute force attacks

## Project Structure

```
soar-api/
├── code/                    # Go application source
│   ├── app/                 # Application container & handlers
│   │   ├── app.go           # Dependency injection container
│   │   ├── handlers.go      # HTTP endpoint handlers
│   │   ├── cloudflarehandler.go
│   │   ├── zscalerhandler.go
│   │   └── recordedfuturehandler.go
│   ├── services/            # External service integrations
│   │   ├── abuseipdb.go
│   │   ├── anomali.go
│   │   ├── zscaler.go
│   │   ├── recordedFuture.go
│   │   ├── azuread.go
│   │   ├── datp.go
│   │   └── cloudflare.go
│   ├── database/            # Data persistence layer
│   │   └── dynamodb.go      # DynamoDB client & operations
│   ├── middleware/          # HTTP middleware
│   │   ├── auth.go          # Cognito authentication
│   │   └── logger.go        # Structured logging
│   ├── models/              # Data structures & types
│   │   ├── ioc.go
│   │   ├── confidence.go
│   │   └── [service models]
│   ├── routes/              # Route definitions
│   │   └── routes.go
│   └── main.go              # Application entrypoint
├── terraform/               # Infrastructure as Code
│   ├── lambda.tf            # Lambda function configuration
│   ├── apigateway.tf        # API Gateway setup
│   ├── dynamodb.tf          # DynamoDB table definitions
│   ├── cognito-oidc.tf      # Cognito authentication
│   ├── kms.tf               # Key management
│   ├── ssm.tf               # Parameter store configuration
│   └── variables.tf         # Configuration variables
├── workflows/               # CI/CD pipelines
│   ├── azure-pipelines.yaml # Azure DevOps pipeline
│   └── ci.yaml              # GitHub Actions
└── Dockerfile               # Container image definition
```

## Data Flow

### Enrichment Request Flow
```
1. Client sends IP/IOC to /api/enrich/ipabusedb
2. API validates request & checks DynamoDB cache
3. If found in cache → Return cached result
4. If not found → Query external service (AbuseIPDB)
5. Service returns threat intelligence
6. API stores result in DynamoDB with TTL
7. Response sent to client
```

### Response/Action Flow
```
1. Client sends incident details to /api/soar/sse/zscaler
2. API validates request & extracts action parameters
3. API authenticates with target service (Zscaler)
4. API submits action request (block URL, IP, etc.)
5. Target service executes action
6. API logs action in DynamoDB audit trail
7. Response with action status sent to client
```

## External Integrations

| Service | Purpose | Type |
|---------|---------|------|
| **AbuseIPDB** | IP reputation database | Enrichment |
| **Anomali** | Threat intelligence platform | Enrichment |
| **RecordedFuture** | Commercial threat feed | Enrichment |
| **Zscaler SSE** | Cloud security service | Response |
| **Azure AD** | Identity and access management | Response |
| **Defender for Endpoint** | Endpoint detection & response | Response |
| **Cloudflare WAF** | Web application firewall | Response |
| **AWS Lambda** | Serverless compute | Infrastructure |
| **DynamoDB** | NoSQL database | Infrastructure |
| **KMS** | Key encryption | Infrastructure |
| **SSM** | Configuration & secrets | Infrastructure |

## Deployment

The API is deployed as a serverless application on AWS using Terraform:

- **Compute**: AWS Lambda with Go runtime
- **API Gateway**: HTTPS regional endpoint
- **Authentication**: AWS Cognito with OIDC
- **Storage**: DynamoDB for caching and audit logs
- **Infrastructure State**: Stored in S3 with Terraform

See `terraform/` directory for infrastructure configuration details.

## Development

### Local Running
```bash
cd code
go run main.go
```
Runs on `http://localhost:8080`

### Build & Deployment
Automated via CI/CD pipelines in `workflows/`
- Tests, linting, and security checks
- Builds Docker image and Lambda package
- Deploys infrastructure via Terraform
