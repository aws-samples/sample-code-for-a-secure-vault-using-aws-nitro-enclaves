# Implementation Plan: `/verify` Endpoint for Attestation Documents

## Overview

Add a `/verify` endpoint to the parent application that:
1. Returns raw attestation documents for **client-side verification**
2. Accepts an optional **nonce** parameter for freshness
3. Includes expected PCR values in **config** for optional parent-side validation

## Architecture

```
Client                    Parent                         Enclave
  |                         |                              |
  |  POST /verify           |                              |
  |  {nonce: "optional"}    |                              |
  |--->-------------------->|                              |
  |                         |  vsock: AttestationRequest   |
  |                         |  {nonce, user_data?}         |
  |                         |--->------------------------->|
  |                         |                              |
  |                         |                              | NSM API:
  |                         |                              | get_attestation_doc()
  |                         |                              |
  |                         |  AttestationResponse         |
  |                         |  {document: bytes}           |
  |                         |<---<-------------------------|
  |                         |                              |
  |                         | Validate PCRs against config |
  |                         | (optional, if configured)    |
  |                         |                              |
  |  VerifyResponse         |                              |
  |  {attestation_document} |                              |
  |<---<--------------------|                              |
```

---

## Implementation Phases

### Phase 1: Enclave - Attestation Generation

#### 1.1 Add NSM FFI declarations (`enclave/src/aws_ne/ffi.rs`)

Add FFI bindings for the Nitro Secure Module API which is already linked via `libnsm.so`:

```rust
// NSM device file descriptor type
pub type NsmFd = i32;

// NSM request/response structures
#[repr(C)]
pub struct NsmMessage {
    pub request: *const u8,
    pub request_len: usize,
    pub response: *mut u8,
    pub response_len: usize,
}

extern "C" {
    /// Initialize NSM library and open device
    pub fn nsm_lib_init() -> NsmFd;

    /// Process an NSM request
    pub fn nsm_process_request(
        fd: NsmFd,
        request: *const u8,
        request_len: usize,
        response: *mut u8,
        response_capacity: usize,
    ) -> i32;
}
```

#### 1.2 Create attestation module (`enclave/src/nsm.rs`)

```rust
//! Nitro Secure Module interface for attestation document generation.

use crate::aws_ne::ffi;
use std::io::{self, ErrorKind};

/// Maximum size for attestation document response
const MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

/// Errors from NSM operations
#[derive(Debug, Clone)]
pub enum Error {
    InitFailed,
    RequestFailed(i32),
    InvalidResponse,
}

/// Generate an attestation document from the Nitro Secure Module.
///
/// # Arguments
/// * `user_data` - Optional application data (max 512 bytes)
/// * `nonce` - Optional nonce for freshness (max 512 bytes)
/// * `public_key` - Optional public key (max 1024 bytes)
///
/// # Returns
/// COSE Sign1 encoded attestation document
pub fn get_attestation_document(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    // Build CBOR request for NSM
    // Call nsm_process_request
    // Parse response and return document bytes
    todo!("Implementation in Phase 1")
}
```

#### 1.3 Add models (`enclave/src/models.rs`)

```rust
/// Request for attestation document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

/// Response containing attestation document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// Base64-encoded COSE Sign1 attestation document
    pub document: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
```

#### 1.4 Update request handling (`enclave/src/main.rs`)

Add request type discrimination:

```rust
/// Request envelope with type tag
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EnclaveRequestType {
    #[serde(rename = "decrypt")]
    Decrypt(EnclaveRequest),
    #[serde(rename = "attestation")]
    Attestation(AttestationRequest),
}
```

Update the main loop to dispatch based on request type.

---

### Phase 2: Parent - Basic Endpoint

#### 2.1 Add models (`parent/src/models.rs`)

```rust
/// Verify endpoint request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct VerifyRequest {
    /// Optional nonce (base64, max 512 bytes decoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 684))]
    pub nonce: Option<String>,

    /// Optional user data (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 684))]
    pub user_data: Option<String>,
}

/// Verify endpoint response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Base64 COSE Sign1 attestation document for client verification
    pub attestation_document: String,

    /// PCR validation result (if enabled in config)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_validation: Option<PcrValidationResult>,
}

/// PCR validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValidationResult {
    pub valid: bool,
    pub pcrs: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}
```

#### 2.2 Add route handler (`parent/src/routes.rs`)

```rust
/// POST /verify - Request attestation document from enclave
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    request.validate()?;

    // Get available enclave
    let enclaves = state.enclaves.get_enclaves().await;
    let enclave = enclaves.first().ok_or(AppError::EnclaveNotFound)?;

    // Send attestation request via vsock
    let response = state.enclaves.attest(enclave.cid, request).await?;

    // Optional PCR validation
    let pcr_validation = if state.options.validate_pcrs {
        Some(validate_pcrs(&response.document, &state.options)?)
    } else {
        None
    };

    Ok(Json(VerifyResponse {
        attestation_document: response.document,
        pcr_validation,
    }))
}
```

#### 2.3 Add route to application (`parent/src/application.rs`)

```rust
Router::new()
    .route("/health", get(routes::health))
    .route("/enclaves", get(routes::get_enclaves))
    .route("/decrypt", post(routes::decrypt))
    .route("/verify", post(routes::verify))  // NEW
    .with_state(state)
```

#### 2.4 Add enclave communication (`parent/src/enclaves.rs`)

```rust
impl Enclaves {
    pub fn attest(&self, cid: u32, request: AttestationRequest) -> Result<AttestationResponse> {
        // Connect via vsock
        // Send attestation request
        // Receive response
    }
}
```

---

### Phase 3: PCR Configuration and Validation

#### 3.1 Add config options (`parent/src/configuration.rs`)

```rust
#[derive(Debug, Clone, Parser)]
pub struct ParentOptions {
    // ... existing ...

    #[arg(long, env("PARENT_EXPECTED_PCR0"))]
    pub expected_pcr0: Option<String>,

    #[arg(long, env("PARENT_EXPECTED_PCR1"))]
    pub expected_pcr1: Option<String>,

    #[arg(long, env("PARENT_EXPECTED_PCR2"))]
    pub expected_pcr2: Option<String>,

    #[arg(long, default_value = "false", env("PARENT_VALIDATE_PCRS"))]
    pub validate_pcrs: bool,
}
```

#### 3.2 Create attestation parser (`parent/src/attestation.rs`)

Minimal CBOR parsing to extract PCRs from COSE Sign1 structure:

```rust
//! Minimal attestation document parsing for PCR extraction.

/// Extract PCR values from base64-encoded attestation document
pub fn extract_pcrs(b64_document: &str) -> Result<BTreeMap<String, String>> {
    // 1. Base64 decode
    // 2. Parse COSE Sign1 to get payload
    // 3. Parse CBOR payload to extract PCRs map
    // 4. Return hex-encoded PCR values
}

/// Validate PCRs against configured expected values
pub fn validate_pcrs(
    pcrs: &BTreeMap<String, String>,
    config: &ParentOptions,
) -> PcrValidationResult {
    // Compare each configured expected PCR against extracted values
}
```

---

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `enclave/src/nsm.rs` | Create | NSM attestation document generation |
| `enclave/src/aws_ne/ffi.rs` | Modify | Add NSM FFI declarations |
| `enclave/src/models.rs` | Modify | Add AttestationRequest/Response |
| `enclave/src/main.rs` | Modify | Add request type dispatch |
| `enclave/src/lib.rs` | Modify | Export nsm module |
| `parent/src/attestation.rs` | Create | CBOR/PCR parsing |
| `parent/src/models.rs` | Modify | Add VerifyRequest/Response |
| `parent/src/routes.rs` | Modify | Add verify handler |
| `parent/src/enclaves.rs` | Modify | Add attest method |
| `parent/src/application.rs` | Modify | Register /verify route |
| `parent/src/configuration.rs` | Modify | Add PCR config options |
| `parent/src/lib.rs` | Modify | Export attestation module |

---

## Dependencies

### No New Cargo Dependencies Required

- **Enclave**: Uses existing `libnsm.so` link (already in build.rs)
- **Parent**: Implements minimal CBOR parsing (~150 lines)

### Alternative (if minimal parsing proves complex)

Consider adding `ciborium` (pure Rust CBOR) if manual parsing is too error-prone.

---

## API Specification

### Request

```http
POST /verify
Content-Type: application/json

{
  "nonce": "base64-encoded-random-bytes",
  "user_data": "optional-base64-data"
}
```

### Response

```json
{
  "attestation_document": "base64-encoded-cose-sign1",
  "pcr_validation": {
    "valid": true,
    "pcrs": {
      "PCR0": "hex-encoded-48-bytes",
      "PCR1": "hex-encoded-48-bytes",
      "PCR2": "hex-encoded-48-bytes"
    },
    "errors": null
  }
}
```

---

## Security Notes

1. **Client-side verification is authoritative** - Parent-side PCR validation is convenience only
2. **Nonce ensures freshness** - Clients should provide random nonce and verify in response
3. **Full verification requires**:
   - Verifying COSE signature against AWS Nitro root certificate
   - Validating certificate chain from cabundle
   - Checking PCR values match expected build

---

## Testing

1. Unit tests for serialization/deserialization
2. Unit tests for CBOR parsing
3. Integration tests with mock enclave
4. End-to-end testing on Nitro hardware
