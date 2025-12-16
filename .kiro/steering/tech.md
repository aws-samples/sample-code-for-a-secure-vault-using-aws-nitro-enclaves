# Technology Stack

## Languages

- **Rust** (Edition 2024): Enclave and parent applications
- **Python 3.13**: API Lambda functions

## Rust Stack

- **Runtime**: Tokio async runtime (parent)
- **Web Framework**: Axum (parent HTTP server)
- **Serialization**: serde, serde_json
- **Crypto**: aws-lc-rs, rustls
- **AWS SDK**: aws-config, aws-credential-types
- **Enclave Communication**: vsock
- **Expression Language**: cel-interpreter
- **CLI Parsing**: clap
- **Error Handling**: anyhow, thiserror
- **Memory**: mimalloc (enclave, musl target)
- **Security**: zeroize for sensitive data

## Python Stack

- **Framework**: AWS Lambda Powertools (logging, tracing, metrics, validation)
- **Validation**: Pydantic (via Powertools parser)
- **HTTP Client**: requests
- **Crypto**: cryptography, hpke
- **ID Generation**: pksuid
- **AWS SDK**: boto3

## Infrastructure

- **IaC**: AWS SAM (Serverless Application Model) + CloudFormation
- **Container**: Docker (enclave and parent images)
- **Build**: docker-bake.hcl for multi-platform builds

## Build Commands

### API (Python Lambda)
```bash
cd api
make setup    # Create venv and install dependencies
make build    # SAM build
make deploy   # SAM deploy
make format   # Run black formatter
make clean    # SAM delete
```

### Enclave (Rust)
```bash
cd enclave
make build           # Build for aarch64-unknown-linux-musl
make build-docker    # Build Docker image
make build-enclave   # Build Nitro Enclave EIF
make clean           # Cargo clean
```

### Parent (Rust)
```bash
cd parent
make build         # Build for aarch64-unknown-linux-gnu
make build-docker  # Build Docker image
make clean         # Cargo clean
```

### Full Deployment
```bash
./deploy.sh  # Interactive deployment script
```

## Code Style

- **Python**: Black formatter, line length 120, target Python 3.13
- **Rust**: Edition 2024, release profile optimized for size (strip, LTO, panic=abort)
