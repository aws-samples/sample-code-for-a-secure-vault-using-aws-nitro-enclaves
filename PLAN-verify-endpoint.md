# Implementation Plan: `/verify` Endpoint for Attestation Documents

## Overview

Add a `/verify` endpoint to the parent application that:
1. Performs **full cryptographic verification** on the parent (COSE signature + certificate chain)
2. Returns raw attestation documents for **client-side verification** (defense-in-depth)
3. Accepts an optional **nonce** parameter for freshness
4. Includes expected PCR values in **config** for PCR validation

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
  |                         |  {document: COSE Sign1}      |
  |                         |<---<-------------------------|
  |                         |                              |
  |                         | 1. Verify COSE signature     |
  |                         | 2. Validate cert chain       |
  |                         | 3. Check PCRs against config |
  |                         |                              |
  |  VerifyResponse         |                              |
  |  {attestation_document, |                              |
  |   verification_result}  |                              |
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

### Phase 2: Parent - Endpoint and Full Verification

#### 2.1 Add dependencies (`parent/Cargo.toml`)

```toml
[dependencies]
# For COSE Sign1 parsing and signature verification
aws-nitro-enclaves-cose = { version = "=0.5.2", default-features = false }

# For certificate chain validation
webpki = { version = "=0.22.4", default-features = false, features = ["alloc"] }

# For CBOR parsing (attestation document payload)
ciborium = { version = "=0.2.2", default-features = false }
```

#### 2.2 Embed AWS Nitro Root Certificate

Create `parent/src/nitro_root_cert.rs`:

```rust
//! AWS Nitro Enclaves Root Certificate
//!
//! Downloaded from: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
//! SHA256: 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c

/// DER-encoded AWS Nitro Enclaves Root Certificate (P-384)
pub const AWS_NITRO_ROOT_CERT_DER: &[u8] = include_bytes!("../certs/AWS_NitroEnclaves_Root-G1.der");

/// Expected SHA256 hash of the root certificate
pub const AWS_NITRO_ROOT_CERT_SHA256: &str =
    "8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c";
```

Download and add the certificate:
```bash
mkdir -p parent/certs
curl -o parent/certs/AWS_NitroEnclaves_Root-G1.zip \
    https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
unzip parent/certs/AWS_NitroEnclaves_Root-G1.zip -d parent/certs/
# Convert PEM to DER if needed
openssl x509 -in parent/certs/root.pem -outform DER -out parent/certs/AWS_NitroEnclaves_Root-G1.der
```

#### 2.3 Add models (`parent/src/models.rs`)

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

/// Verify endpoint response - includes both raw attestation AND verification results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Base64 COSE Sign1 attestation document for client verification
    pub attestation_document: String,

    /// Full verification result from parent
    pub verification: VerificationResult,
}

/// Complete verification result from parent-side checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall verification passed (all checks succeeded)
    pub verified: bool,

    /// COSE Sign1 signature verification against enclave certificate
    pub signature_valid: bool,

    /// Certificate chain validates to AWS Nitro root
    pub certificate_chain_valid: bool,

    /// PCR validation result (if configured)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_validation: Option<PcrValidationResult>,

    /// Attestation document metadata
    pub document_info: DocumentInfo,

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

    /// Nonce echoed back (if provided in request)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// User data echoed back (if provided in request)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

/// PCR validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValidationResult {
    /// All configured PCRs matched
    pub valid: bool,

    /// Extracted PCR values (hex encoded)
    pub pcrs: std::collections::BTreeMap<String, String>,

    /// PCR validation errors
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}
```

#### 2.4 Create attestation verification module (`parent/src/attestation.rs`)

```rust
//! Full attestation document verification.
//!
//! Implements COSE Sign1 signature verification, certificate chain validation,
//! and PCR extraction/validation for AWS Nitro Enclave attestation documents.

use aws_nitro_enclaves_cose::CoseSign1;
use std::collections::BTreeMap;
use anyhow::{Result, anyhow, Context};

use crate::nitro_root_cert::AWS_NITRO_ROOT_CERT_DER;
use crate::models::{VerificationResult, PcrValidationResult, DocumentInfo};
use crate::configuration::ParentOptions;

/// Parsed attestation document
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

/// Verify an attestation document completely.
///
/// Performs:
/// 1. CBOR/COSE Sign1 parsing
/// 2. Signature verification using enclave certificate
/// 3. Certificate chain validation to AWS Nitro root
/// 4. PCR extraction and optional validation
pub fn verify_attestation(
    b64_document: &str,
    config: &ParentOptions,
) -> Result<VerificationResult> {
    let mut errors = Vec::new();

    // 1. Base64 decode
    let doc_bytes = base64_decode(b64_document)
        .context("Failed to base64 decode attestation document")?;

    // 2. Parse COSE Sign1 structure
    let cose_sign1 = CoseSign1::from_bytes(&doc_bytes)
        .map_err(|e| anyhow!("Failed to parse COSE Sign1: {:?}", e))?;

    // 3. Extract and parse attestation payload (CBOR)
    let parsed = parse_attestation_payload(cose_sign1.get_payload()?)
        .context("Failed to parse attestation payload")?;

    // 4. Verify COSE signature using enclave certificate
    let signature_valid = verify_cose_signature(&cose_sign1, &parsed.certificate)
        .unwrap_or_else(|e| {
            errors.push(format!("Signature verification failed: {}", e));
            false
        });

    // 5. Validate certificate chain to AWS Nitro root
    let certificate_chain_valid = validate_certificate_chain(
        &parsed.certificate,
        &parsed.cabundle,
        AWS_NITRO_ROOT_CERT_DER,
    ).unwrap_or_else(|e| {
        errors.push(format!("Certificate chain validation failed: {}", e));
        false
    });

    // 6. PCR validation (if configured)
    let pcr_validation = if config.validate_pcrs {
        Some(validate_pcrs(&parsed.pcrs, config))
    } else {
        // Still extract PCRs for response, just don't validate
        Some(PcrValidationResult {
            valid: true,
            pcrs: pcrs_to_hex_map(&parsed.pcrs),
            errors: None,
        })
    };

    // 7. Build document info
    let document_info = DocumentInfo {
        module_id: parsed.module_id,
        timestamp: parsed.timestamp,
        digest: parsed.digest,
        nonce: parsed.nonce.map(|n| base64_encode(&n)),
        user_data: parsed.user_data.map(|d| base64_encode(&d)),
    };

    let verified = signature_valid
        && certificate_chain_valid
        && pcr_validation.as_ref().map(|p| p.valid).unwrap_or(true);

    Ok(VerificationResult {
        verified,
        signature_valid,
        certificate_chain_valid,
        pcr_validation,
        document_info,
        errors: if errors.is_empty() { None } else { Some(errors) },
    })
}

/// Verify COSE Sign1 signature using the enclave's certificate
fn verify_cose_signature(cose: &CoseSign1, cert_der: &[u8]) -> Result<bool> {
    // Extract public key from certificate
    // Verify signature using P-384 ECDSA
    todo!("Implementation")
}

/// Validate certificate chain from enclave cert to AWS Nitro root
fn validate_certificate_chain(
    enclave_cert: &[u8],
    cabundle: &[Vec<u8>],
    root_cert: &[u8],
) -> Result<bool> {
    // Build chain: enclave_cert -> intermediates -> root
    // Validate using webpki
    // Check temporal validity, key usage, path constraints
    todo!("Implementation")
}

/// Parse CBOR attestation payload
fn parse_attestation_payload(payload: &[u8]) -> Result<ParsedAttestation> {
    // Use ciborium to parse CBOR
    // Extract all fields per AWS spec
    todo!("Implementation")
}

/// Validate PCRs against configured expected values
fn validate_pcrs(
    pcrs: &BTreeMap<u8, Vec<u8>>,
    config: &ParentOptions,
) -> PcrValidationResult {
    let mut errors = Vec::new();
    let hex_pcrs = pcrs_to_hex_map(pcrs);

    // Check PCR0
    if let Some(ref expected) = config.expected_pcr0 {
        match hex_pcrs.get("PCR0") {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Some(actual) => errors.push(format!(
                "PCR0 mismatch: expected {}, got {}", expected, actual
            )),
            None => errors.push("PCR0 not found in attestation".to_string()),
        }
    }

    // Check PCR1
    if let Some(ref expected) = config.expected_pcr1 {
        match hex_pcrs.get("PCR1") {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Some(actual) => errors.push(format!(
                "PCR1 mismatch: expected {}, got {}", expected, actual
            )),
            None => errors.push("PCR1 not found in attestation".to_string()),
        }
    }

    // Check PCR2
    if let Some(ref expected) = config.expected_pcr2 {
        match hex_pcrs.get("PCR2") {
            Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Some(actual) => errors.push(format!(
                "PCR2 mismatch: expected {}, got {}", expected, actual
            )),
            None => errors.push("PCR2 not found in attestation".to_string()),
        }
    }

    PcrValidationResult {
        valid: errors.is_empty(),
        pcrs: hex_pcrs,
        errors: if errors.is_empty() { None } else { Some(errors) },
    }
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
/// This endpoint:
/// 1. Requests an attestation document from the enclave
/// 2. Verifies the COSE Sign1 signature
/// 3. Validates the certificate chain to AWS Nitro root
/// 4. Optionally validates PCRs against configured values
/// 5. Returns both raw attestation (for client verification) and verification results
#[tracing::instrument(skip(state, request))]
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    // 1. Validate request
    request.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;

    // 2. Get available enclave
    let enclaves = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    // 3. Select enclave (random for load balancing)
    let index = fastrand::usize(..enclaves.len());
    let enclave = enclaves.get(index).ok_or(AppError::EnclaveNotFound)?;
    let cid: u32 = enclave.enclave_cid.try_into()
        .map_err(|_| AppError::InternalServerError)?;

    // 4. Build attestation request
    let attestation_request = AttestationRequest {
        nonce: request.nonce.clone(),
        user_data: request.user_data.clone(),
    };

    // 5. Send to enclave via vsock
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

    // 6. Check for enclave-side errors
    if let Some(error) = response.error {
        return Err(AppError::AttestationError(error));
    }

    // 7. Perform full verification
    let verification = attestation::verify_attestation(&response.document, &state.options)
        .map_err(|e| {
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

### Phase 3: Configuration

#### 3.1 Add config options (`parent/src/configuration.rs`)

```rust
#[derive(Debug, Clone, Parser)]
pub struct ParentOptions {
    // ... existing fields ...

    /// Expected PCR0 value (SHA384 hex, 96 chars) for enclave image hash
    #[arg(long, env("PARENT_EXPECTED_PCR0"))]
    pub expected_pcr0: Option<String>,

    /// Expected PCR1 value (SHA384 hex) for kernel/bootstrap
    #[arg(long, env("PARENT_EXPECTED_PCR1"))]
    pub expected_pcr1: Option<String>,

    /// Expected PCR2 value (SHA384 hex) for application
    #[arg(long, env("PARENT_EXPECTED_PCR2"))]
    pub expected_pcr2: Option<String>,

    /// Enable PCR validation (requires at least one expected_pcrN to be set)
    #[arg(long, default_value = "false", env("PARENT_VALIDATE_PCRS"), action = ArgAction::SetTrue)]
    pub validate_pcrs: bool,
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
| `parent/src/attestation.rs` | Create | Full COSE/cert chain verification |
| `parent/src/nitro_root_cert.rs` | Create | Embedded AWS Nitro root certificate |
| `parent/certs/` | Create | Directory for certificate files |
| `parent/src/models.rs` | Modify | Add VerifyRequest/Response/VerificationResult |
| `parent/src/routes.rs` | Modify | Add verify handler |
| `parent/src/enclaves.rs` | Modify | Add attest method |
| `parent/src/application.rs` | Modify | Register /verify route |
| `parent/src/configuration.rs` | Modify | Add PCR config options |
| `parent/src/lib.rs` | Modify | Export attestation, nitro_root_cert modules |
| `parent/Cargo.toml` | Modify | Add new dependencies |

---

## Dependencies

### Parent - New Dependencies

```toml
[dependencies]
# COSE Sign1 parsing and verification
aws-nitro-enclaves-cose = { version = "=0.5.2", default-features = false }

# Certificate chain validation
webpki = { version = "=0.22.4", default-features = false, features = ["alloc"] }

# CBOR parsing for attestation payload
ciborium = { version = "=0.2.2", default-features = false }

# Hex encoding for PCR values
hex = { version = "=0.4.3", default-features = false, features = ["alloc"] }
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
  "nonce": "base64-encoded-random-bytes",
  "user_data": "optional-base64-data"
}
```

### Response

```json
{
  "attestation_document": "base64-encoded-cose-sign1",
  "verification": {
    "verified": true,
    "signature_valid": true,
    "certificate_chain_valid": true,
    "pcr_validation": {
      "valid": true,
      "pcrs": {
        "PCR0": "hex-encoded-48-bytes-sha384",
        "PCR1": "hex-encoded-48-bytes-sha384",
        "PCR2": "hex-encoded-48-bytes-sha384"
      },
      "errors": null
    },
    "document_info": {
      "module_id": "i-0abc123-enc0123abc",
      "timestamp": 1703412345678,
      "digest": "SHA384",
      "nonce": "base64-echoed-nonce",
      "user_data": null
    },
    "errors": null
  }
}
```

### Error Response

```json
{
  "code": 500,
  "message": "attestation error: NSM request failed"
}
```

---

## Security Notes

1. **Defense-in-depth**: Both parent AND client can verify the attestation
2. **Parent verification is convenience**: Clients should still verify independently for maximum security
3. **Nonce ensures freshness**: Clients should provide random nonce and verify it's echoed back
4. **Root certificate trust**: The AWS Nitro root cert is embedded at build time; its hash should be verified

### Certificate Chain Validation

The validation follows AWS specifications:
1. Build chain: `[enclave_cert, intermediate_N, ..., intermediate_1, root]`
2. Verify each certificate:
   - Temporal validity (not expired)
   - Key usage (keyCertSign for CA certs, digitalSignature for enclave cert)
   - Basic constraints (pathLenConstraint)
3. Verify signatures up the chain
4. Anchor trust at the AWS Nitro root certificate

### COSE Signature Verification

1. Extract enclave certificate from attestation document
2. Parse certificate to get P-384 public key
3. Verify COSE Sign1 signature (ECDSA P-384) using that key

---

## Testing

### Unit Tests

1. COSE Sign1 parsing with test vectors
2. Certificate chain validation with mock chains
3. PCR extraction and validation
4. Request/response serialization

### Integration Tests

1. Mock enclave returning sample attestation documents
2. Full verification flow with known-good documents
3. Error handling for malformed documents

### End-to-End Tests

1. Deploy to Nitro Enclave EC2 instance
2. Verify real attestation documents
3. Confirm nonce is correctly echoed
4. Validate PCRs match build measurements
