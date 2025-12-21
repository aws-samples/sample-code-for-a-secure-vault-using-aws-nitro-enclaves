# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a secure vault solution for storing PII/PHI data using AWS Nitro Enclaves. It implements a three-tier architecture:

1. **API Tier** (`api/`): Python Lambda functions using AWS Lambda Powertools, deployed via SAM
2. **Parent Tier** (`parent/`): Rust application running on EC2 with Axum HTTP server, handles vsock communication to enclave
3. **Enclave Tier** (`enclave/`): Rust application running inside Nitro Enclave, performs KMS decryption and HPKE cryptography

## Build Commands

### Rust Components (Workspace at root)
```bash
cargo build                              # Build both enclave and parent
cargo fmt --all -- --check               # Check formatting
cargo clippy --all-features              # Lint (warnings are denied in CI)
cargo test --verbose                     # Run tests

# Individual component builds
make -C enclave build                    # Build enclave binary
make -C enclave build-docker             # Build enclave Docker image
make -C parent build                     # Build parent binary
make -C parent build-docker              # Build parent Docker image
```

### Python API
```bash
cd api
make setup                               # Create venv and install dependencies
make build                               # SAM build
make deploy                              # SAM deploy
```

### Docker Multi-Platform Builds
```bash
docker buildx bake -f docker-bake.hcl    # Build both parent and enclave images
```

## Architecture

```
Client → API Gateway → Lambda (Python)
                         ↓
                      DynamoDB (metadata/audit)
                         ↓
         NLB → NGINX → Parent (Rust/Axum) → vsock → Enclave (Rust)
                                                        ↓
                                                   KMS Decrypt
```

**Communication:**
- API ↔ Parent: HTTPS via Network Load Balancer
- Parent ↔ Enclave: vsock (Nitro-specific virtual socket)
- Enclave → KMS: vsock proxy forwarding to HTTPS

The Parent can only communicate to the Enclave over the vsock. Whenever possible, the Enclave must ensure it returns all error states back to the Parent over the vsock.

**Key Data Flow (Decrypt):**
1. Lambda retrieves encrypted vault from DynamoDB
2. Parent receives request, extracts IAM credentials from IMDSv2
3. Enclave decrypts secret key via KMS, then decrypts attributes using HPKE
4. CEL expressions optionally transform decrypted data before returning

## Key Technologies

- **Rust**: Axum 0.8, Tokio, aws-lc-rs, rustls (post-quantum TLS)
- **Python**: AWS Lambda Powertools, boto3
- **Infrastructure**: CloudFormation templates, SAM, Docker Buildx
- **Cryptography**: HPKE for encryption, AWS KMS for key management, CEL for transformations

## Build Targets

- **Enclave**: `aarch64-unknown-linux-musl` (statically linked with mimalloc)
- **Parent**: `aarch64-unknown-linux-gnu` (dynamically linked)

## Code Style

- Line length: 120 characters
- Indentation: 4 spaces for Python/Rust, 2 spaces for YAML/JSON
- Python formatting: Black
- Rust: cargo fmt

## CI/CD

GitHub Actions runs on ARM64 (`ubuntu-24.04-arm`):
- `rust.yml`: Format check, build, clippy, tests
- `security_audit.yml`: Daily RustSec vulnerability scanning
- `docker-bake.yml`: Multi-platform Docker builds

Dependencies must be pinned to exact versions to ensure reproducibility. We want to avoid introducing new dependencies. Leverage the Rust std library whenever possible.