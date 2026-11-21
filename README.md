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
- **Authorization**: Every route requires a Cognito access token with the required OAuth scope

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
- Valid Cognito access token with the required scope (client-credentials flow)
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
├── terraform/               # Reusable Terraform module + Terragrunt wrappers
│   ├── main.tf              # Application composition
│   ├── variables.tf         # Validated inputs
│   ├── terragrunt.hcl       # Shared provider/backend configuration
│   ├── environments/        # dev/ and prod/ wrappers (separate accounts)
│   └── modules/             # Supporting AWS resource modules
├── .github/workflows/       # Checks, PR plans, gated dev → prod deploys
├── Makefile                 # Checks, image build/push and plan/apply
└── Dockerfile               # Lambda and standalone HTTP image targets
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

### Prerequisites (existing, not managed by this Terraform)

- Versioned, encrypted S3 state bucket per account
- One private ECR repository shared by dev and prod, in the same region as both
  Lambdas, with **immutable tags** (no tag-mutability exclusions). Prod deploys
  the digest already verified in dev; see `.github/workflows/README.md` for the
  cross-account repository-policy requirements.
- External KMS keys (SSM SecureStrings + application ciphertext) and the
  Azure-integrated Cognito identity pool
- Vendor credentials in SSM under `/<project>/<env>/…` (base64 KMS ciphertext,
  decrypted at request time by `code/services/aws.go`)

### Local deployment commands

```bash
export TG_ACCOUNT_ID=... TG_STATE_BUCKET=... TG_ECR_REPOSITORY_URL=...   # see environments/<env>/env.hcl
make check                          # fmt, validate, go vet/gofmt, go test
make image-push ENV=dev             # build + push; prints the image digest
TG_IMAGE_DIGEST=sha256:... make plan ENV=dev
TG_IMAGE_DIGEST=sha256:... make apply ENV=dev
make output ENV=dev
```

See [.github/workflows/README.md](.github/workflows/README.md) for the CI/CD
pipeline, versioning, and required GitHub configuration.

## Development

### Local Running
```bash
cd code
go run main.go
```
Runs on `http://localhost:8080`

