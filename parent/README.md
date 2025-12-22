# Parent Vault

The parent tier of the AWS Nitro Enclaves secure vault solution.

## Overview

This component runs on the EC2 instance and provides:

- **HTTP API** for decrypt requests from the API tier
- **IAM credential management** via IMDS with automatic caching
- **Nitro Enclave lifecycle management** (discovery and launch)
- **vsock communication** with enclaves using length-prefixed JSON

## Architecture

```
                    +----------------+
    HTTP Request -> | Axum Router    |
                    | - Rate Limit   |
                    | - Timeout      |
                    | - Body Limit   |
                    +-------+--------+
                            |
                            v
                    +----------------+
                    | Route Handler  |
                    | - Validation   |
                    +-------+--------+
                            |
            +---------------+---------------+
            |                               |
            v                               v
    +---------------+               +---------------+
    | IMDS Client   |               | Enclaves      |
    | - Cred Cache  |               | - nitro-cli   |
    +---------------+               | - vsock       |
                                    +-------+-------+
                                            |
                                            v
                                    +---------------+
                                    | Nitro Enclave |
                                    +---------------+
```

## Building

```bash
# Build for development
cargo build -p parent-vault

# Build for production (requires cross-compilation for ARM64)
make -C parent build-docker
```

## Running

```bash
parent-vault \
    --host 127.0.0.1 \
    --port 8080 \
    --role my-iam-role
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | HTTP server listen address | `127.0.0.1` |
| `--port` | HTTP server listen port | `8080` |
| `--role` | IAM role name for credential assumption | None |
| `--skip-refresh-enclaves` | Skip enclave refresh loop | `false` |
| `--skip-run-enclaves` | Skip launching new enclaves | `false` |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PARENT_HTTP_HOST` | Listen address | `127.0.0.1` |
| `PARENT_HTTP_PORT` | Listen port | `8080` |
| `PARENT_ROLE_NAME` | IAM role name | None |
| `PARENT_SKIP_REFRESH_ENCLAVES` | Skip enclave refresh loop | `false` |
| `PARENT_SKIP_RUN_ENCLAVES` | Skip auto-launching enclaves | `false` |
| `RUST_LOG` | Log level | `info,tower_http=debug` |

## API Endpoints

### GET /health

Health check endpoint.

**Response:**
```json
{"status": "ok"}
```

### GET /enclaves

List running Nitro Enclaves.

**Response:** Array of enclave descriptions.

### POST /decrypt

Decrypt vault fields using a Nitro Enclave.

**Request Body:**
```json
{
    "vault_id": "v_...",
    "region": "us-east-1",
    "fields": {"field_name": "encrypted_value"},
    "suite_id": "base64_encoded_suite_id",
    "encrypted_private_key": "base64_encoded_key",
    "expressions": {"field_name": "CEL expression"},
    "encoding": "utf-8"
}
```

**Response:**
```json
{
    "fields": {"field_name": "decrypted_value"},
    "errors": null
}
```

## Middleware Configuration

| Middleware | Configuration |
|------------|---------------|
| Rate Limiting | 100 requests/second per IP |
| Request Timeout | 30 seconds |
| Body Size Limit | 1 MB |

## Testing

```bash
# Run all tests
cargo test -p parent-vault

# Run with logging
RUST_LOG=debug cargo test -p parent-vault -- --nocapture

# Run a specific test
cargo test -p parent-vault test_validate_aws_region
```

## Module Documentation

Generate and view the documentation:

```bash
cargo doc -p parent-vault --open
```

## Security

- **Credential Caching**: IAM credentials are refreshed 60 seconds before expiry
- **Credential Protection**: Sensitive data is zeroized on drop via `zeroize`
- **Debug Redaction**: Credential debug output shows `[REDACTED]`
- **Request Validation**: Strict size limits on all fields
- **Rate Limiting**: Prevents denial of service attacks
