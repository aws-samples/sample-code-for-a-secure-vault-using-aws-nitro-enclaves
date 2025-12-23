# Design Document: Parent Improvements

## Overview

This design document details the implementation of security, reliability, and code quality improvements for the AWS Nitro Enclaves Vault parent module. The improvements mirror those applied to the enclave module, focusing on no-panic Rust patterns, dependency reduction, and code optimization.

The parent is a Rust application running on an EC2 instance that provides an HTTP API (via Axum) and bridges requests to Nitro Enclaves over vsock.

## Architecture

The parent module consists of the following components:

```
┌─────────────────────────────────────────────────────────────┐
│                     Parent Application                       │
├─────────────────────────────────────────────────────────────┤
│  main.rs          │ Entry point, tokio runtime, tracing     │
│                   │ setup, enclave refresh loop             │
├───────────────────┼─────────────────────────────────────────┤
│  application.rs   │ Axum HTTP server setup, middleware      │
│                   │ (rate limiting, timeout, body limit)    │
├───────────────────┼─────────────────────────────────────────┤
│  routes.rs        │ HTTP route handlers (health, decrypt,   │
│                   │ get_enclaves)                           │
├───────────────────┼─────────────────────────────────────────┤
│  protocol.rs      │ vsock message framing (length-prefixed) │
│                   │ send_message(), recv_message()          │
├───────────────────┼─────────────────────────────────────────┤
│  models.rs        │ Request/Response types, Credential,     │
│                   │ validation                              │
├───────────────────┼─────────────────────────────────────────┤
│  enclaves.rs      │ Enclave lifecycle management,           │
│                   │ nitro-cli integration, vsock comm       │
├───────────────────┼─────────────────────────────────────────┤
│  imds.rs          │ IAM credential caching from IMDS        │
├───────────────────┼─────────────────────────────────────────┤
│  errors.rs        │ Application error types, HTTP mapping   │
├───────────────────┼─────────────────────────────────────────┤
│  constants.rs     │ Configuration constants                 │
├───────────────────┼─────────────────────────────────────────┤
│  configuration.rs │ CLI argument parsing with clap          │
└───────────────────┴─────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Protocol Module Updates (protocol.rs)

Replace byteorder crate with std methods and add safe memory allocation:

```rust
use std::{
    io::{Read, Write},
    mem::size_of,
};

use anyhow::{Result, anyhow, bail};
use vsock::VsockStream;

use crate::constants::MAX_MESSAGE_SIZE;

/// Sends a message over a vsock stream.
#[inline]
#[tracing::instrument(skip(stream, msg))]
pub fn send_message(stream: &mut VsockStream, msg: String) -> Result<()> {
    // Write 8-byte little-endian length header using std method
    let payload_len: u64 = msg
        .len()
        .try_into()
        .map_err(|err| anyhow!("failed to compute message length: {:?}", err))?;
    let header_buf = payload_len.to_le_bytes();
    stream
        .write_all(&header_buf)
        .map_err(|err| anyhow!("failed to write message header: {:?}", err))?;

    // Write message payload
    stream
        .write_all(msg.as_bytes())
        .map_err(|err| anyhow!("failed to write message body: {:?}", err))?;

    Ok(())
}

/// Receives a message from a vsock stream.
#[inline]
#[tracing::instrument(skip(stream))]
pub fn recv_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    // Read 8-byte little-endian length header
    let mut size_buf = [0; size_of::<u64>()];
    stream
        .read_exact(&mut size_buf)
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    // Convert using std method
    let size = u64::from_le_bytes(size_buf);

    // Validate message size to prevent memory exhaustion
    if size > MAX_MESSAGE_SIZE {
        bail!(
            "message size {} exceeds maximum allowed size {}",
            size,
            MAX_MESSAGE_SIZE
        );
    }

    // Safe conversion from u64 to usize
    let size_usize: usize = size
        .try_into()
        .map_err(|_| anyhow!("message size {} too large for platform", size))?;

    // Allocate buffer with error handling to prevent panic on allocation failure
    let mut payload_buffer = Vec::new();
    payload_buffer
        .try_reserve(size_usize)
        .map_err(|_| anyhow!("failed to allocate {} bytes for message", size_usize))?;
    payload_buffer.resize(size_usize, 0);

    stream
        .read_exact(&mut payload_buffer)
        .map_err(|err| anyhow!("failed to read message body: {:?}", err))?;

    Ok(payload_buffer)
}
```

### 2. Safe Enclave Selection (routes.rs)

Replace direct indexing with safe `.get()` access:

```rust
// Current (unsafe):
let index = fastrand::usize(..enclaves.len());
let cid: u32 = enclaves[index]
    .enclave_cid
    .try_into()
    .map_err(|_| AppError::InternalServerError)?;

// Updated (safe):
let index = fastrand::usize(..enclaves.len());
let enclave = enclaves
    .get(index)
    .ok_or(AppError::EnclaveNotFound)?;
let cid: u32 = enclave
    .enclave_cid
    .try_into()
    .map_err(|_| AppError::InternalServerError)?;
```

### 3. Main Function Error Handling (main.rs)

The main function already handles errors well, but we should audit for any `.unwrap()` or `.expect()` calls:

```rust
// Current (has unwrap_or_else):
.with_env_filter(EnvFilter::new(
    std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
))

// This is acceptable - unwrap_or_else doesn't panic, it provides a default
```

### 4. Protocol Test Updates

Update tests to use std methods instead of byteorder:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_length_header_encoding() {
        let len: u64 = 12345;
        let buf = len.to_le_bytes();
        assert_eq!(u64::from_le_bytes(buf), 12345);
    }

    #[test]
    fn test_length_header_little_endian_byte_order() {
        let len: u64 = 0x0102030405060708;
        let buf = len.to_le_bytes();
        // Little-endian: least significant byte first
        assert_eq!(buf, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }
}
```

## Data Models

### Protocol Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| MAX_MESSAGE_SIZE | 10,485,760 (10 MB) | Prevent memory exhaustion DoS |
| ENCLAVE_PORT | 5050 | vsock port for enclave communication |

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do.*

### Property 1: Protocol Message Round-Trip

*For any* valid message string within MAX_MESSAGE_SIZE, encoding it with `to_le_bytes()` and decoding with `from_le_bytes()` SHALL produce the identical length value.

**Validates: Requirements 1.3**

### Property 2: Message Size Bounds

*For any* message size value greater than MAX_MESSAGE_SIZE, the recv_message() function SHALL return an error without allocating a buffer of that size.

**Validates: Requirements 2.1, 2.2**

### Property 3: Safe Indexing

*For any* enclave list and any random index within bounds, accessing via `.get()` SHALL never panic and SHALL return the correct enclave.

**Validates: Requirements 9.1, 9.2**

## Error Handling

### Error Categories

| Category | Handling | Response to Client |
|----------|----------|-------------------|
| Protocol errors | Log and return error | 500 Internal Server Error |
| Validation errors | Log and return error | 400 Bad Request |
| Enclave not found | Log and return error | 404 Not Found |
| Credential errors | Log and return error | 500 Internal Server Error |
| Connection errors | Log and continue | N/A |

### No-Panic Rust Strategy

The parent follows the same "No-Panic Rust" methodology as the enclave:

1. **Replace `[]` indexing with `.get()`**: All slice/array access uses `.get()` with explicit error handling
2. **Use checked arithmetic**: For user-influenced values
3. **Use `try_reserve()`**: Fallible allocation instead of panicking on OOM
4. **Return `Result`**: All errors propagated via Result, never panic
5. **Inherit workspace lints**: `clippy::unwrap_used`, `clippy::expect_used` as warnings

## Testing Strategy

### Unit Tests

Unit tests verify specific examples and edge cases:

1. **Protocol tests**: Test message framing with specific sizes
2. **Length header tests**: Verify little-endian encoding
3. **Validation tests**: Test request validation

### Property-Based Tests

Property-based tests verify universal properties using the `proptest` crate:

**Configuration**: Minimum 100 iterations per property test

## Implementation Notes

### Backward Compatibility

All changes maintain backward compatibility with the existing wire protocol.

### Workspace Lints

Clippy lints are now defined at the workspace level in `Cargo.toml`:

```toml
[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
indexing_slicing = "warn"
```

Both `enclave` and `parent` crates inherit these via:

```toml
[lints]
workspace = true
```

### Dependencies to Remove

After migration, remove from `parent/Cargo.toml`:
```toml
byteorder = { version = "=1.5.0", default-features = false }
```
