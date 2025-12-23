---
inclusion: always
---

# Technology Stack

## Languages & Editions

| Language | Version | Usage |
|----------|---------|-------|
| Rust | Edition 2024 | Enclave and parent applications |
| Python | 3.13 | API Lambda functions |

## Rust Dependencies

Use these crates for the specified purposes:

| Category | Crate(s) | Notes |
|----------|----------|-------|
| Async Runtime | tokio | Parent app only |
| Web Framework | axum | Parent HTTP server |
| Serialization | serde, serde_json | All Rust code |
| Crypto | aws-lc-rs, rustls | Prefer over OpenSSL |
| AWS SDK | aws-config, aws-credential-types | |
| Enclave Comms | vsock | Parent ↔ Enclave |
| Expressions | cel-interpreter | CEL evaluation |
| CLI | clap | Command-line parsing |
| Errors | anyhow (apps), thiserror (libs) | |
| Memory | mimalloc | Enclave only (musl target) |
| Security | zeroize | REQUIRED for sensitive data |

## Python Dependencies

| Category | Package(s) | Notes |
|----------|------------|-------|
| Framework | aws-lambda-powertools | Logging, tracing, metrics, validation |
| Validation | pydantic | Via Powertools parser |
| HTTP | requests | External API calls |
| Crypto | cryptography, hpke | HPKE encryption |
| IDs | pksuid | Unique ID generation |
| AWS | boto3 | AWS service clients |

## Infrastructure

- IaC: AWS SAM + CloudFormation (all `*_template.yml` files)
- Containers: Docker with `docker-bake.hcl` for multi-platform builds
- Targets: `aarch64-unknown-linux-musl` (enclave), `aarch64-unknown-linux-gnu` (parent)

## Build Commands

Each component has a `Makefile`. Use these commands:

```bash
# API (Python)
cd api && make setup   # Create venv, install deps
cd api && make build   # SAM build
cd api && make deploy  # SAM deploy
cd api && make format  # Black formatter
cd api && make clean   # SAM delete

# Enclave (Rust)
cd enclave && make build          # aarch64-unknown-linux-musl
cd enclave && make build-docker   # Docker image
cd enclave && make build-enclave  # Nitro Enclave EIF

# Parent (Rust)
cd parent && make build         # aarch64-unknown-linux-gnu
cd parent && make build-docker  # Docker image

# Full deployment
./deploy.sh
```

## Code Style Rules

### Python
- Formatter: Black
- Line length: 120 characters
- Target: Python 3.13
- Run `make format` before committing

### Rust
- Edition: 2024
- Release profile: optimized for size (strip, LTO, panic=abort)
- Use `#[must_use]` on functions returning values that shouldn't be ignored
- Wrap sensitive data types with `zeroize::Zeroizing<T>`

## Coding Conventions

### Rust
- Prefer `thiserror` for library error types, `anyhow` for application errors
- Use `#[derive(Debug, Clone, Serialize, Deserialize)]` on data types
- All public APIs must have doc comments
- No `unwrap()` in production code; use `?` or explicit error handling

### Python
- Use type hints on all function signatures
- Use Pydantic models for request/response validation
- Use Lambda Powertools decorators for logging, tracing, metrics
- All source files require MIT-0 license header

## Security Requirements

- NEVER log sensitive/plaintext data
- Use `zeroize` crate to clear sensitive data from memory in Rust
- Validate all inputs at API boundary with Pydantic
- Use constant-time comparison for secrets
