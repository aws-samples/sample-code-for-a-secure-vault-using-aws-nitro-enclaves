# AWS Nitro Enclaves Vault

A secure vault solution for storing and protecting sensitive data (PII/PHI) using AWS Nitro Enclaves.

## Purpose

Provides a secure mechanism to store sensitive data encrypted at rest, with decryption only possible through approved channels within isolated Nitro Enclave environments.

## Key Features

- Flexible data model supporting PII fields (email, SSN, DOB, address, phone, etc.)
- HPKE encryption (RFC 9180) using P-384 curve, HKDF-SHA384, and AES-256-GCM
- Symmetric keys secured via AWS KMS
- CEL (Common Expression Language) support for field transformations during decryption
- Audit logging of all vault operations

## Architecture Overview

Three-tier architecture:
1. **API Tier**: API Gateway + Lambda (Python) + DynamoDB for metadata/audit
2. **Decryption Tier**: EC2 instances with NGINX, parent application (Rust), vsock proxy
3. **Enclave Tier**: Nitro Enclave running enclave application (Rust) for secure decryption
