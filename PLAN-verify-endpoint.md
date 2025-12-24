# Implementation Plan: `/verify` Endpoint for Attestation Documents

## Overview

Add a `/verify` endpoint to the parent application that:
1. Performs **cryptographic verification** (COSE signature + certificate chain)
2. Uses **reconstruct-verify** approach for PCR validation (Trail of Bits recommendation)
3. Client provides expected PCRs per-request (no parent-side config)
4. Returns raw attestation document for **client-side re-verification** (defense-in-depth)
5. Enforces **minimum nonce length** and **timestamp validation**

**Security Model**: Following [Trail of Bits recommendations](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/), we reconstruct the attestation payload with expected PCR values and verify the signature against the reconstructed payload. This protects against parsing bugs that could cause incorrect PCR extraction.

## Architecture

```
Client                    Parent                         Enclave
  |                         |                              |
  |  POST /verify           |                              |
  |  {nonce,                |                              |
  |   expected_pcrs}        |                              |
  |--->-------------------->|                              |
  |                         |  vsock: AttestationRequest   |
  |                         |  {nonce, user_data?}         |
  |                         |--->------------------------->|
  |                         |                              |
  |                         |                              | NSM API:
  |                         |                              | get_attestation_doc()
  |                         |                              |
  |                         |  AttestationResponse         |
  |                         |  {document: COSE Sign1}      |
  |                         |<---<-------------------------|
  |                         |                              |
  |                         | 1. Validate cert chain       |
  |                         | 2. Reconstruct payload with  |
  |                         |    client's expected PCRs    |
  |                         | 3. Verify signature against  |
  |                         |    reconstructed payload     |
  |                         | 4. Check timestamp freshness |
  |                         |                              |
  |  VerifyResponse         |                              |
  |  {attestation_document, |                              |
  |   pcrs_match: true}     |                              |
  |<---<--------------------|                              |
```

---

## Security Design (Trail of Bits Compliance)

### Reconstruct-Verify Approach

Instead of parsing PCRs and comparing them (vulnerable to parsing bugs), we:

1. Parse attestation document to extract non-PCR fields
2. **Reconstruct** the payload using client-provided expected PCRs
3. Verify COSE signature against the **reconstructed** payload
4. If signature valid → PCRs match (cryptographically proven)

```rust
// Traditional (vulnerable to parsing bugs):
let parsed_pcrs = parse_pcrs(payload);
let match = parsed_pcrs == expected_pcrs;  // Bug here could miss mismatch

// Reconstruct-verify (Trail of Bits recommended):
let reconstructed = rebuild_payload_with_expected_pcrs(payload, expected_pcrs);
let match = verify_signature(cose, reconstructed);  // Crypto proves match
```

### Additional Security Measures

| Measure | Implementation |
|---------|----------------|
| Minimum nonce length | Enforce ≥16 bytes (128 bits) |
| Timestamp validation | Check attestation is recent (configurable max age) |
| Nonce echo verification | Verify nonce in response matches request |
| Certificate chain | Validate to embedded AWS Nitro root |
| Root cert hash | Verify SHA256 matches known value |

### Trust Model

**IMPORTANT**: The parent instance is considered **untrusted** in the threat model.

- Parent-side verification is a **convenience** for clients
- Security-conscious clients should **re-verify** the raw attestation document
- The `attestation_document` field is always returned for independent verification
- Assume parent's kernel could be compromised (per Trail of Bits guidance)

---

## Implementation Phases

### Phase 1: Enclave - Attestation Generation

#### 1.1 Add NSM FFI declarations (`enclave/src/aws_ne/ffi.rs`)

```rust
// NSM device file descriptor type
pub type NsmFd = i32;

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

/// Minimum nonce length (16 bytes = 128 bits)
pub const MIN_NONCE_LENGTH: usize = 16;

/// Maximum size for attestation document response
const MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

/// Errors from NSM operations
#[derive(Debug, Clone)]
pub enum Error {
    InitFailed,
    RequestFailed(i32),
    InvalidResponse,
    NonceTooShort,
}

/// Generate an attestation document from the Nitro Secure Module.
///
/// # Arguments
/// * `user_data` - Optional application data (max 512 bytes)
/// * `nonce` - Nonce for freshness (min 16 bytes, max 512 bytes)
/// * `public_key` - Optional public key (max 1024 bytes)
///
/// # Returns
/// COSE Sign1 encoded attestation document
pub fn get_attestation_document(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    // Enforce minimum nonce length
    if let Some(n) = nonce {
        if n.len() < MIN_NONCE_LENGTH {
            return Err(Error::NonceTooShort);
        }
    }

    // Build CBOR request for NSM
    // Call nsm_process_request
    // Parse response and return document bytes
}
```

#### 1.3 Add models (`enclave/src/models.rs`)

```rust
/// Request for attestation document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRequest {
    /// Nonce for freshness (base64, min 16 bytes decoded)
    pub nonce: String,

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

---

### Phase 2: Parent - Endpoint and Verification

#### 2.1 Add dependencies (`parent/Cargo.toml`)

```toml
[dependencies]
# For COSE Sign1 parsing and signature verification
aws-nitro-enclaves-cose = { version = "=0.5.2", default-features = false }

# For certificate chain validation
webpki = { version = "=0.22.4", default-features = false, features = ["alloc"] }

# For CBOR parsing and serialization (attestation payload)
ciborium = { version = "=0.2.2", default-features = false }

# Hex encoding for PCR values
hex = { version = "=0.4.3", default-features = false, features = ["alloc"] }
```

#### 2.2 Embed AWS Nitro Root Certificate

Create `parent/src/nitro_root_cert.rs`:

```rust
//! AWS Nitro Enclaves Root Certificate
//!
//! Downloaded from: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
//! SHA256: 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c

use sha2::{Sha256, Digest};

/// DER-encoded AWS Nitro Enclaves Root Certificate (P-384)
pub const AWS_NITRO_ROOT_CERT_DER: &[u8] = include_bytes!("../certs/AWS_NitroEnclaves_Root-G1.der");

/// Expected SHA256 hash of the root certificate
pub const AWS_NITRO_ROOT_CERT_SHA256: &str =
    "8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c";

/// Verify the embedded root certificate hash matches expected value
pub fn verify_root_cert_hash() -> bool {
    let hash = Sha256::digest(AWS_NITRO_ROOT_CERT_DER);
    let hash_hex = hex::encode(hash);
    hash_hex == AWS_NITRO_ROOT_CERT_SHA256
}
```

#### 2.3 Add models (`parent/src/models.rs`)

```rust
use std::collections::BTreeMap;

/// Minimum nonce length in bytes (before base64 encoding)
pub const MIN_NONCE_BYTES: usize = 16;

/// Default maximum attestation age in milliseconds (5 minutes)
pub const DEFAULT_MAX_AGE_MS: u64 = 300_000;

/// Verify endpoint request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct VerifyRequest {
    /// Nonce for freshness (base64, min 16 bytes decoded = 24 chars base64)
    #[validate(length(min = 24, max = 684))]
    pub nonce: String,

    /// Expected PCR values (hex encoded, 96 chars for SHA384)
    /// Keys: "PCR0", "PCR1", "PCR2", etc.
    pub expected_pcrs: BTreeMap<String, String>,

    /// Optional user data (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 684))]
    pub user_data: Option<String>,

    /// Maximum attestation age in milliseconds (default: 300000 = 5 min)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_ms: Option<u64>,
}

/// Verify endpoint response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Base64 COSE Sign1 attestation document for client re-verification
    pub attestation_document: String,

    /// Verification result from parent
    pub verification: VerificationResult,
}

/// Verification result using reconstruct-verify approach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall verification passed (all checks succeeded)
    pub verified: bool,

    /// Certificate chain validates to AWS Nitro root
    pub certificate_chain_valid: bool,

    /// PCRs match (verified via payload reconstruction + signature check)
    pub pcrs_match: bool,

    /// Nonce in attestation matches request
    pub nonce_valid: bool,

    /// Attestation timestamp is within max_age_ms
    pub timestamp_valid: bool,

    /// Attestation document metadata
    pub document_info: DocumentInfo,

    /// Actual PCR values from attestation (for client reference)
    pub actual_pcrs: BTreeMap<String, String>,

    /// Any verification errors encountered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Metadata extracted from attestation document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    /// Enclave module ID
    pub module_id: String,

    /// Attestation timestamp (milliseconds since epoch)
    pub timestamp: u64,

    /// Digest algorithm used (e.g., "SHA384")
    pub digest: String,

    /// Nonce echoed back (base64)
    pub nonce: String,

    /// User data echoed back (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}
```

#### 2.4 Create attestation verification module (`parent/src/attestation.rs`)

```rust
//! Attestation document verification using reconstruct-verify approach.
//!
//! Following Trail of Bits recommendations, we reconstruct the attestation
//! payload with expected PCR values and verify the signature against it.
//! This protects against parsing bugs that could cause incorrect PCR extraction.
//!
//! Reference: https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/

use aws_nitro_enclaves_cose::CoseSign1;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow, Context};

use crate::nitro_root_cert::AWS_NITRO_ROOT_CERT_DER;
use crate::models::{VerificationResult, DocumentInfo, DEFAULT_MAX_AGE_MS};

/// Parsed attestation document (before PCR reconstruction)
pub struct ParsedAttestation {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

/// Verify attestation using reconstruct-verify approach.
///
/// # Arguments
/// * `b64_document` - Base64-encoded COSE Sign1 attestation document
/// * `expected_pcrs` - Client-provided expected PCR values (hex)
/// * `expected_nonce` - Nonce that should be in attestation (base64)
/// * `max_age_ms` - Maximum acceptable age of attestation
///
/// # Security
/// Uses Trail of Bits recommended approach: reconstruct payload with
/// expected PCRs and verify signature against reconstruction.
pub fn verify_attestation(
    b64_document: &str,
    expected_pcrs: &BTreeMap<String, String>,
    expected_nonce: &str,
    max_age_ms: Option<u64>,
) -> Result<VerificationResult> {
    let mut errors = Vec::new();
    let max_age = max_age_ms.unwrap_or(DEFAULT_MAX_AGE_MS);

    // 1. Base64 decode
    let doc_bytes = base64_decode(b64_document)
        .context("Failed to base64 decode attestation document")?;

    // 2. Parse COSE Sign1 structure
    let cose_sign1 = CoseSign1::from_bytes(&doc_bytes)
        .map_err(|e| anyhow!("Failed to parse COSE Sign1: {:?}", e))?;

    // 3. Extract and parse attestation payload (CBOR)
    let parsed = parse_attestation_payload(cose_sign1.get_payload()?)
        .context("Failed to parse attestation payload")?;

    // 4. Validate certificate chain to AWS Nitro root
    let certificate_chain_valid = validate_certificate_chain(
        &parsed.certificate,
        &parsed.cabundle,
        AWS_NITRO_ROOT_CERT_DER,
    ).unwrap_or_else(|e| {
        errors.push(format!("Certificate chain validation failed: {}", e));
        false
    });

    // 5. Convert expected PCRs from hex to bytes
    let expected_pcrs_bytes = parse_expected_pcrs(expected_pcrs)
        .map_err(|e| {
            errors.push(format!("Invalid expected PCRs: {}", e));
        }).ok();

    // 6. RECONSTRUCT-VERIFY: Build payload with expected PCRs and verify signature
    let pcrs_match = if let Some(ref expected) = expected_pcrs_bytes {
        reconstruct_and_verify(&cose_sign1, &parsed, expected, &parsed.certificate)
            .unwrap_or_else(|e| {
                errors.push(format!("Reconstruct-verify failed: {}", e));
                false
            })
    } else {
        false
    };

    // 7. Verify nonce matches
    let nonce_valid = verify_nonce(&parsed.nonce, expected_nonce)
        .unwrap_or_else(|e| {
            errors.push(format!("Nonce verification failed: {}", e));
            false
        });

    // 8. Verify timestamp is recent
    let timestamp_valid = verify_timestamp(parsed.timestamp, max_age)
        .unwrap_or_else(|e| {
            errors.push(format!("Timestamp verification failed: {}", e));
            false
        });

    // 9. Extract actual PCRs for client reference
    let actual_pcrs = pcrs_to_hex_map(&parsed.pcrs);

    // 10. Build document info
    let document_info = DocumentInfo {
        module_id: parsed.module_id,
        timestamp: parsed.timestamp,
        digest: parsed.digest,
        nonce: parsed.nonce.map(|n| base64_encode(&n)).unwrap_or_default(),
        user_data: parsed.user_data.map(|d| base64_encode(&d)),
    };

    let verified = certificate_chain_valid && pcrs_match && nonce_valid && timestamp_valid;

    Ok(VerificationResult {
        verified,
        certificate_chain_valid,
        pcrs_match,
        nonce_valid,
        timestamp_valid,
        document_info,
        actual_pcrs,
        errors: if errors.is_empty() { None } else { Some(errors) },
    })
}

/// Reconstruct attestation payload with expected PCRs and verify signature.
///
/// This is the Trail of Bits recommended approach - instead of parsing PCRs
/// and comparing, we rebuild the payload and check if signature validates.
fn reconstruct_and_verify(
    cose: &CoseSign1,
    parsed: &ParsedAttestation,
    expected_pcrs: &BTreeMap<u8, Vec<u8>>,
    cert_der: &[u8],
) -> Result<bool> {
    // 1. Reconstruct CBOR payload with expected PCRs
    let reconstructed_payload = rebuild_attestation_payload(parsed, expected_pcrs)?;

    // 2. Rebuild COSE Sign1 with reconstructed payload
    let reconstructed_cose = rebuild_cose_sign1(cose, &reconstructed_payload)?;

    // 3. Extract public key from certificate
    let public_key = extract_p384_public_key(cert_der)?;

    // 4. Verify signature - if valid, PCRs match!
    verify_ecdsa_p384_signature(&reconstructed_cose, &public_key)
}

/// Rebuild attestation payload CBOR with different PCR values
fn rebuild_attestation_payload(
    parsed: &ParsedAttestation,
    new_pcrs: &BTreeMap<u8, Vec<u8>>,
) -> Result<Vec<u8>> {
    // Use ciborium to build CBOR map with:
    // - module_id, timestamp, digest from parsed
    // - pcrs from new_pcrs (the expected values)
    // - certificate, cabundle, nonce, user_data, public_key from parsed
    todo!("CBOR serialization implementation")
}

/// Verify nonce in attestation matches expected
fn verify_nonce(actual: &Option<Vec<u8>>, expected_b64: &str) -> Result<bool> {
    let expected = base64_decode(expected_b64)?;
    match actual {
        Some(actual_nonce) => Ok(actual_nonce == &expected),
        None => Ok(false),
    }
}

/// Verify timestamp is within acceptable age
fn verify_timestamp(timestamp_ms: u64, max_age_ms: u64) -> Result<bool> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis() as u64;

    // Check if attestation is from the future (clock skew tolerance: 60s)
    if timestamp_ms > now_ms + 60_000 {
        return Ok(false);
    }

    // Check if attestation is too old
    let age_ms = now_ms.saturating_sub(timestamp_ms);
    Ok(age_ms <= max_age_ms)
}

/// Validate certificate chain from enclave cert to AWS Nitro root
fn validate_certificate_chain(
    enclave_cert: &[u8],
    cabundle: &[Vec<u8>],
    root_cert: &[u8],
) -> Result<bool> {
    // Build chain: enclave_cert -> intermediates -> root
    // Validate using webpki:
    // - Temporal validity (not expired)
    // - Key usage (keyCertSign for CA certs, digitalSignature for enclave cert)
    // - Basic constraints (pathLenConstraint)
    // - Signature chain
    todo!("Certificate chain validation implementation")
}

/// Parse CBOR attestation payload
fn parse_attestation_payload(payload: &[u8]) -> Result<ParsedAttestation> {
    // Use ciborium to parse CBOR map
    // Extract all fields per AWS spec
    todo!("CBOR parsing implementation")
}

fn parse_expected_pcrs(expected: &BTreeMap<String, String>) -> Result<BTreeMap<u8, Vec<u8>>> {
    let mut result = BTreeMap::new();
    for (key, hex_value) in expected {
        let index: u8 = key
            .strip_prefix("PCR")
            .ok_or_else(|| anyhow!("Invalid PCR key: {}", key))?
            .parse()?;
        let bytes = hex::decode(hex_value)?;
        if bytes.len() != 48 {
            return Err(anyhow!("PCR{} must be 48 bytes (SHA384), got {}", index, bytes.len()));
        }
        result.insert(index, bytes);
    }
    Ok(result)
}

fn pcrs_to_hex_map(pcrs: &BTreeMap<u8, Vec<u8>>) -> BTreeMap<String, String> {
    pcrs.iter()
        .map(|(k, v)| (format!("PCR{}", k), hex::encode(v)))
        .collect()
}
```

#### 2.5 Add route handler (`parent/src/routes.rs`)

```rust
/// POST /verify - Request and verify attestation document from enclave
///
/// Uses Trail of Bits recommended reconstruct-verify approach:
/// 1. Requests attestation document from enclave
/// 2. Validates certificate chain to AWS Nitro root
/// 3. Reconstructs payload with client's expected PCRs
/// 4. Verifies signature against reconstructed payload
/// 5. Validates nonce and timestamp freshness
///
/// If signature validates → PCRs cryptographically match expected values
#[tracing::instrument(skip(state, request))]
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    // 1. Validate request
    request.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;

    // 2. Validate minimum nonce length (decoded)
    let nonce_bytes = base64_decode(&request.nonce)
        .map_err(|_| AppError::ValidationError("Invalid base64 nonce".to_string()))?;
    if nonce_bytes.len() < MIN_NONCE_BYTES {
        return Err(AppError::ValidationError(
            format!("Nonce must be at least {} bytes", MIN_NONCE_BYTES)
        ));
    }

    // 3. Get available enclave
    let enclaves = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    // 4. Select enclave (random for load balancing)
    let index = fastrand::usize(..enclaves.len());
    let enclave = enclaves.get(index).ok_or(AppError::EnclaveNotFound)?;
    let cid: u32 = enclave.enclave_cid.try_into()
        .map_err(|_| AppError::InternalServerError)?;

    // 5. Build attestation request
    let attestation_request = AttestationRequest {
        nonce: request.nonce.clone(),
        user_data: request.user_data.clone(),
    };

    // 6. Send to enclave via vsock
    let enclaves_ref = state.enclaves.clone();
    let port = constants::ENCLAVE_PORT;
    let response: AttestationResponse =
        tokio::task::spawn_blocking(move || enclaves_ref.attest(cid, port, attestation_request))
            .await
            .map_err(|_| AppError::InternalServerError)?
            .map_err(|e| {
                tracing::error!("[parent] attestation failed: {:?}", e);
                AppError::AttestationError(e.to_string())
            })?;

    // 7. Check for enclave-side errors
    if let Some(error) = response.error {
        return Err(AppError::AttestationError(error));
    }

    // 8. Perform reconstruct-verify validation
    let verification = attestation::verify_attestation(
        &response.document,
        &request.expected_pcrs,
        &request.nonce,
        request.max_age_ms,
    ).map_err(|e| {
        tracing::error!("[parent] verification failed: {:?}", e);
        AppError::AttestationError(e.to_string())
    })?;

    Ok(Json(VerifyResponse {
        attestation_document: response.document,
        verification,
    }))
}
```

#### 2.6 Add route to application (`parent/src/application.rs`)

```rust
Router::new()
    .route("/health", get(routes::health))
    .route("/enclaves", get(routes::get_enclaves))
    .route("/decrypt", post(routes::decrypt))
    .route("/verify", post(routes::verify))  // NEW
    .with_state(state)
```

#### 2.7 Add enclave communication (`parent/src/enclaves.rs`)

```rust
impl Enclaves {
    /// Request an attestation document from an enclave.
    #[tracing::instrument(skip(self, request))]
    pub fn attest(
        &self,
        cid: u32,
        port: u32,
        request: AttestationRequest,
    ) -> Result<AttestationResponse, AppError> {
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))?;

        // Wrap in envelope with type tag
        let envelope = serde_json::json!({
            "type": "attestation",
            "nonce": request.nonce,
            "user_data": request.user_data,
        });
        let msg = serde_json::to_string(&envelope)
            .map_err(|_| AppError::InternalServerError)?;

        send_message(&mut stream, msg)?;

        let response = recv_message(&mut stream)?;
        let result: AttestationResponse = serde_json::from_slice(&response)?;

        Ok(result)
    }
}
```

---

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `enclave/src/nsm.rs` | Create | NSM attestation generation with nonce validation |
| `enclave/src/aws_ne/ffi.rs` | Modify | Add NSM FFI declarations |
| `enclave/src/models.rs` | Modify | Add AttestationRequest/Response |
| `enclave/src/main.rs` | Modify | Add request type dispatch |
| `enclave/src/lib.rs` | Modify | Export nsm module |
| `parent/src/attestation.rs` | Create | Reconstruct-verify implementation |
| `parent/src/nitro_root_cert.rs` | Create | Embedded AWS Nitro root certificate |
| `parent/certs/` | Create | Directory for certificate files |
| `parent/src/models.rs` | Modify | Add VerifyRequest/Response with expected_pcrs |
| `parent/src/routes.rs` | Modify | Add verify handler |
| `parent/src/enclaves.rs` | Modify | Add attest method |
| `parent/src/application.rs` | Modify | Register /verify route |
| `parent/src/lib.rs` | Modify | Export attestation, nitro_root_cert modules |
| `parent/Cargo.toml` | Modify | Add new dependencies |

---

## Dependencies

### Parent - New Dependencies

```toml
[dependencies]
# COSE Sign1 parsing and signature verification
aws-nitro-enclaves-cose = { version = "=0.5.2", default-features = false }

# Certificate chain validation
webpki = { version = "=0.22.4", default-features = false, features = ["alloc"] }

# CBOR parsing AND serialization (for payload reconstruction)
ciborium = { version = "=0.2.2", default-features = false }

# Hex encoding for PCR values
hex = { version = "=0.4.3", default-features = false, features = ["alloc"] }

# SHA256 for root cert hash verification
sha2 = { version = "=0.10.8", default-features = false }
```

### Enclave - No New Dependencies

Uses existing `libnsm.so` link (already in build.rs).

---

## API Specification

### Request

```http
POST /verify
Content-Type: application/json

{
  "nonce": "base64-random-min-16-bytes",
  "expected_pcrs": {
    "PCR0": "hex-96-chars-sha384",
    "PCR1": "hex-96-chars-sha384",
    "PCR2": "hex-96-chars-sha384"
  },
  "user_data": "optional-base64-data",
  "max_age_ms": 300000
}
```

### Response (Success)

```json
{
  "attestation_document": "base64-encoded-cose-sign1",
  "verification": {
    "verified": true,
    "certificate_chain_valid": true,
    "pcrs_match": true,
    "nonce_valid": true,
    "timestamp_valid": true,
    "document_info": {
      "module_id": "i-0abc123-enc0123abc",
      "timestamp": 1703412345678,
      "digest": "SHA384",
      "nonce": "base64-echoed-nonce",
      "user_data": null
    },
    "actual_pcrs": {
      "PCR0": "hex-value",
      "PCR1": "hex-value",
      "PCR2": "hex-value"
    },
    "errors": null
  }
}
```

### Response (PCR Mismatch)

```json
{
  "attestation_document": "base64-encoded-cose-sign1",
  "verification": {
    "verified": false,
    "certificate_chain_valid": true,
    "pcrs_match": false,
    "nonce_valid": true,
    "timestamp_valid": true,
    "document_info": { ... },
    "actual_pcrs": {
      "PCR0": "actual-hex-value-different-from-expected"
    },
    "errors": ["Reconstruct-verify failed: signature mismatch"]
  }
}
```

### Error Response

```json
{
  "code": 400,
  "message": "Nonce must be at least 16 bytes"
}
```

---

## Security Notes

### Trail of Bits Compliance

| Recommendation | Implementation |
|----------------|----------------|
| Reconstruct payload, don't parse-then-compare | ✅ `reconstruct_and_verify()` |
| Verify AWS root cert hash | ✅ `verify_root_cert_hash()` |
| Enforce minimum nonce length | ✅ 16 bytes minimum |
| Check attestation timestamp | ✅ `verify_timestamp()` with configurable max age |
| Check PCR-1 and PCR-2, not just PCR-0 | ✅ Client provides which PCRs to check |
| Parent is untrusted | ✅ Raw attestation returned for client re-verification |

### Trust Model

**Parent instance is UNTRUSTED**. Per Trail of Bits:
> "Assume that the parent instance's kernel is controlled by the attacker"

Therefore:
- Parent verification is **convenience**, not security guarantee
- `attestation_document` is always returned for **independent client verification**
- Security-conscious clients should re-verify the raw document themselves

### What Gets Verified

| Check | Verified By | Trust Level |
|-------|-------------|-------------|
| Certificate chain | Parent | Convenience |
| PCRs match (via reconstruction) | Parent | Convenience |
| Nonce freshness | Parent | Convenience |
| Timestamp age | Parent | Convenience |
| Raw attestation | Client | Authoritative |

---

## Testing

### Unit Tests

1. Payload reconstruction with known test vectors
2. COSE signature verification
3. Certificate chain validation with mock chains
4. Nonce length validation
5. Timestamp freshness checks
6. PCR hex parsing and validation

### Integration Tests

1. Mock enclave returning sample attestation documents
2. Reconstruct-verify with matching PCRs → success
3. Reconstruct-verify with mismatched PCRs → failure
4. Expired timestamp → failure
5. Short nonce → rejection

### End-to-End Tests

1. Deploy to Nitro Enclave EC2 instance
2. Verify real attestation documents
3. Confirm reconstruct-verify correctly detects PCR mismatches
4. Validate timestamp freshness works with real attestations

---

## References

- [Trail of Bits: Images and Attestation (Feb 2024)](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/)
- [Trail of Bits: Attack Surface (Sept 2024)](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/)
- [AWS: Verifying the Root of Trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- [AWS: Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)
