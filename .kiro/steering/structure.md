# Project Structure

```
├── api/                    # Python Lambda API
│   ├── src/app/           # Application code
│   │   ├── routers/       # API route handlers
│   │   ├── resources/     # AWS resource clients (DynamoDB, KMS)
│   │   ├── models.py      # Pydantic models and vault schema
│   │   ├── vault.py       # Core vault operations
│   │   ├── encryptors.py  # HPKE encryption logic
│   │   └── lambda_handler.py  # Lambda entry point
│   ├── dependencies/      # Lambda layer dependencies
│   └── template.yml       # SAM template
│
├── enclave/               # Rust Nitro Enclave application
│   └── src/
│       ├── main.rs        # Enclave entry point (vsock listener)
│       ├── hpke.rs        # HPKE decryption
│       ├── kms.rs         # KMS integration
│       ├── expressions.rs # CEL expression execution
│       ├── models.rs      # Request/response types
│       └── protocol.rs    # Vsock message protocol
│
├── parent/                # Rust parent instance application
│   └── src/
│       ├── main.rs        # Parent entry point
│       ├── application.rs # Axum app setup
│       ├── routes.rs      # HTTP route handlers
│       ├── enclaves.rs    # Enclave management
│       ├── imds.rs        # EC2 instance metadata
│       └── protocol.rs    # Vsock communication
│
├── canary/                # Python canary Lambda for monitoring
│   └── src/app/
│
├── docs/                  # MkDocs documentation
│
├── scripts/               # Development scripts
│
├── Cargo.toml             # Rust workspace root
├── deploy.sh              # Main deployment script
├── uninstall.sh           # Cleanup script
│
# CloudFormation Templates
├── vpc_template.yml       # VPC infrastructure
├── kms_template.yml       # KMS key setup
├── ci_template.yml        # CI/CD pipeline
├── vault_template.yml     # Vault EC2 infrastructure
└── deploy_template.yml    # Deployment orchestration
```

## Key Patterns

- **Workspace**: Rust workspace with `enclave` and `parent` members
- **Lambda Layers**: Python dependencies in `api/dependencies/`
- **SAM**: Each Lambda component has its own `template.yml` and `samconfig.toml`
- **Makefiles**: Each component has a Makefile for common operations
- **License Headers**: All source files include MIT-0 license header
