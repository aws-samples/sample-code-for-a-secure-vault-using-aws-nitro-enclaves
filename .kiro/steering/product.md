---
inclusion: always
---

# AWS Nitro Enclaves Vault

Secure vault for storing and protecting sensitive data (PII/PHI) using AWS Nitro Enclaves.

## Core Concepts

- **Vault**: Stores encrypted sensitive data with metadata in DynamoDB
- **HPKE Encryption**: RFC 9180 using P-384, HKDF-SHA384, AES-256-GCM
- **CEL Expressions**: Field transformations during decryption (masking, formatting)
- **Attestation**: Nitro Enclave attestation ensures decryption only in trusted environments

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   API Tier      │     │ Decryption Tier │     │  Enclave Tier   │
│                 │     │                 │     │                 │
│ API Gateway     │────▶│ EC2 + NGINX     │────▶│ Nitro Enclave   │
│ Lambda (Python) │     │ Parent (Rust)   │vsock│ Enclave (Rust)  │
│ DynamoDB        │     │                 │     │ KMS Decrypt     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Data Flow

1. **Store**: API encrypts data with HPKE → stores ciphertext + metadata in DynamoDB
2. **Retrieve**: Request goes to parent → forwarded via vsock to enclave → KMS decrypts symmetric key → HPKE decrypts data → CEL transforms applied → response returned

## Security Principles

- Plaintext sensitive data NEVER exists outside the enclave
- KMS key policy restricts decryption to attested enclaves only
- All vault operations are audit logged
- Use `zeroize` for sensitive data in Rust code
- Validate all inputs at API boundary with Pydantic

## Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Lambda API | `api/src/app/` | REST API, encryption, DynamoDB ops |
| Parent App | `parent/src/` | HTTP server, enclave management, vsock proxy |
| Enclave App | `enclave/src/` | KMS integration, HPKE decryption, CEL execution |
| Canary | `canary/src/app/` | Health monitoring |

## When Modifying Code

- Encryption logic changes: Update both `api/src/app/encryptors.py` and `enclave/src/hpke.rs`
- New vault fields: Update `api/src/app/models.py` and `enclave/src/models.rs`
- CEL functions: Modify `enclave/src/expressions.rs` and `enclave/src/functions.rs`
- API routes: Add to `api/src/app/routers/`
- Protocol changes: Update both `parent/src/protocol.rs` and `enclave/src/protocol.rs`
