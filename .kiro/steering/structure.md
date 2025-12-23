---
inclusion: always
---

# Project Structure

## Directory Layout

| Path | Language | Purpose |
|------|----------|---------|
| `api/` | Python | Lambda API - encryption, DynamoDB, REST endpoints |
| `enclave/` | Rust | Nitro Enclave - KMS decrypt, HPKE, CEL execution |
| `parent/` | Rust | EC2 parent - Axum HTTP server, vsock proxy |
| `canary/` | Python | Health monitoring Lambda |
| `docs/` | Markdown | MkDocs documentation |
| `scripts/` | Shell | Development utilities |

## Component File Mapping

### API (`api/src/app/`)
- `lambda_handler.py` - Lambda entry point
- `routers/` - API route handlers (add new endpoints here)
- `resources/` - AWS clients (DynamoDB, KMS)
- `models.py` - Pydantic models, vault schema
- `vault.py` - Core vault operations
- `encryptors.py` - HPKE encryption (sync with `enclave/src/hpke.rs`)

### Enclave (`enclave/src/`)
- `main.rs` - Vsock listener entry point
- `hpke.rs` - HPKE decryption (sync with `api/src/app/encryptors.py`)
- `kms.rs` - KMS integration
- `expressions.rs` - CEL expression execution
- `functions.rs` - CEL custom functions
- `models.rs` - Request/response types (sync with `api/src/app/models.py`)
- `protocol.rs` - Vsock message protocol (sync with `parent/src/protocol.rs`)

### Parent (`parent/src/`)
- `main.rs` - Application entry point
- `application.rs` - Axum app setup
- `routes.rs` - HTTP route handlers
- `enclaves.rs` - Enclave lifecycle management
- `imds.rs` - EC2 instance metadata client
- `protocol.rs` - Vsock communication (sync with `enclave/src/protocol.rs`)

## Infrastructure Templates

| Template | Purpose |
|----------|---------|
| `vpc_template.yml` | VPC, subnets, security groups |
| `kms_template.yml` | KMS key with enclave attestation policy |
| `vault_template.yml` | EC2 instance, ASG, ALB |
| `ci_template.yml` | CodePipeline, CodeBuild |
| `deploy_template.yml` | Deployment orchestration |
| `api/template.yml` | Lambda functions, API Gateway, DynamoDB |
| `canary/template.yml` | Canary Lambda |

## Key Conventions

- Rust workspace root: `Cargo.toml` with `enclave` and `parent` members
- Each component has a `Makefile` for build/deploy/clean operations
- Python Lambda layers: dependencies in `*/dependencies/requirements.txt`
- SAM config: each Lambda has `template.yml` + `samconfig.toml`
- All source files require MIT-0 license header

## Cross-Component Sync Points

When modifying these areas, update both sides:

| Change Type | Files to Update |
|-------------|-----------------|
| Encryption/Decryption | `api/.../encryptors.py` ↔ `enclave/src/hpke.rs` |
| Data Models | `api/.../models.py` ↔ `enclave/src/models.rs` |
| Vsock Protocol | `parent/src/protocol.rs` ↔ `enclave/src/protocol.rs` |
| CEL Functions | `enclave/src/expressions.rs` + `enclave/src/functions.rs` |
