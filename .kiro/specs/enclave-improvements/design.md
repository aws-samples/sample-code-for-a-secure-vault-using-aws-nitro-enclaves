# Design Document: Enclave Improvements

## Overview

This design document details the implementation of security, reliability, and code quality improvements for the AWS Nitro Enclaves Vault enclave module. The improvements are organized into four phases: Critical Fixes, Security Hardening, Code Quality, and Housekeeping.

The enclave is a Rust application running inside a Nitro Enclave that receives encrypted field data via vsock, decrypts it using HPKE with KMS-protected private keys, optionally applies CEL transformations, and returns the results.

## Architecture

The enclave module consists of the following components:

```
┌─────────────────────────────────────────────────────────────┐
│                     Enclave Application                      │
├─────────────────────────────────────────────────────────────┤
│  main.rs          │ Entry point, vsock listener, client     │
│                   │ handling loop                            │
├───────────────────┼─────────────────────────────────────────┤
│  protocol.rs      │ Message framing (length-prefixed)       │
│                   │ send_message(), recv_message()          │
├───────────────────┼─────────────────────────────────────────┤
│  models.rs        │ Request/Response types, Suite,          │
│                   │ EncryptedData, field decryption         │
├───────────────────┼─────────────────────────────────────────┤
│  kms.rs           │ KMS decrypt via FFI, private key        │
│                   │ extraction                               │
├───────────────────┼─────────────────────────────────────────┤
│  hpke.rs          │ HPKE decryption using rustls            │
├───────────────────┼─────────────────────────────────────────┤
│  expressions.rs   │ CEL expression execution                │
├───────────────────┼─────────────────────────────────────────┤
│  functions.rs     │ Custom CEL functions (hash, encode)     │
├───────────────────┼─────────────────────────────────────────┤
│  constants.rs     │ Suite IDs, port, encoding constants     │
├───────────────────┼─────────────────────────────────────────┤
│  utils.rs         │ Base64 decode utility                   │
├───────────────────┼─────────────────────────────────────────┤
│  aws_ne/          │ FFI wrapper for Nitro Enclaves SDK      │
└───────────────────┴─────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Suite Enum (models.rs)

Replace the current `Suite(Vec<u8>)` tuple struct with a type-safe enum:

```rust
/// HPKE cipher suite identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// P-256 curve with HKDF-SHA256 and AES-256-GCM
    P256,
    /// P-384 curve with HKDF-SHA384 and AES-256-GCM
    P384,
    /// P-521 curve with HKDF-SHA512 and AES-256-GCM
    P521,
}

impl Suite {
    /// Returns the encapped key size in bytes for this suite
    pub fn encapped_key_size(&self) -> usize {
        match self {
            Suite::P256 => 65,
            Suite::P384 => 97,
            Suite::P521 => 133,
        }
    }

    /// Returns the HPKE suite implementation
    pub fn get_hpke_suite(&self) -> &'static dyn Hpke {
        match self {
            Suite::P256 => DH_KEM_P256_HKDF_SHA256_AES_256,
            Suite::P384 => DH_KEM_P384_HKDF_SHA384_AES_256,
            Suite::P521 => DH_KEM_P521_HKDF_SHA512_AES_256,
        }
    }

    /// Returns the ECDSA signing algorithm for this suite
    pub fn get_signing_algorithm(&self) -> &'static EcdsaSigningAlgorithm {
        match self {
            Suite::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            Suite::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            Suite::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
        }
    }
}

impl TryFrom<&str> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let bytes = base64_decode(value)?;
        match bytes.as_slice() {
            s if s == P256 => Ok(Suite::P256),
            s if s == P384 => Ok(Suite::P384),
            s if s == P521 => Ok(Suite::P521),
            _ => bail!("unknown suite identifier"),
        }
    }
}
```

### 2. Protocol Constants and Validation (protocol.rs)

Add message size limits and ensure complete writes:

```rust
/// Maximum allowed message size (10 MB)
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024;

pub fn send_message(stream: &mut VsockStream, msg: String) -> Result<()> {
    let payload_len: u64 = msg.len().try_into()?;
    let mut header_buf = [0; size_of::<u64>()];
    LittleEndian::write_u64(&mut header_buf, payload_len);
    
    // Use write_all for complete writes
    stream.write_all(&header_buf)?;
    stream.write_all(msg.as_bytes())?;
    
    Ok(())
}

pub fn recv_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    let mut size_buf = [0; size_of::<u64>()];
    stream.read_exact(&mut size_buf)?;
    
    let size = LittleEndian::read_u64(&size_buf);
    
    // Validate message size before allocation
    if size > MAX_MESSAGE_SIZE {
        bail!("message size {} exceeds maximum {}", size, MAX_MESSAGE_SIZE);
    }
    
    let mut payload_buffer = vec![0; size as usize];
    stream.read_exact(&mut payload_buffer)?;
    
    Ok(payload_buffer)
}
```

### 3. EncryptedData with Suite-Aware Parsing (models.rs)

Update binary parsing to accept suite information:

```rust
impl EncryptedData {
    pub fn from_hex(value: &str) -> Result<Self> {
        // Existing implementation - hex format includes '#' separator
        let (hex_encapped_key, hex_ciphertext) = value
            .split_once('#')
            .ok_or_else(|| anyhow!("invalid hex format: missing '#' separator"))?;
        
        Ok(Self {
            encapped_key: HEXLOWER.decode(hex_encapped_key.as_bytes())?,
            ciphertext: HEXLOWER.decode(hex_ciphertext.as_bytes())?,
        })
    }

    pub fn from_binary(value: &str, suite: &Suite) -> Result<Self> {
        let data = base64_decode(value)?;
        let key_size = suite.encapped_key_size();
        
        if data.len() < key_size {
            bail!(
                "encrypted data too short: {} bytes, need at least {} for {:?}",
                data.len(),
                key_size,
                suite
            );
        }
        
        Ok(Self {
            encapped_key: data[..key_size].to_vec(),
            ciphertext: data[key_size..].to_vec(),
        })
    }
}
```

### 4. Field Count Limits (models.rs)

Add validation in decrypt_fields:

```rust
/// Maximum number of fields allowed per request
pub const MAX_FIELDS: usize = 1000;

impl EnclaveRequest {
    pub fn decrypt_fields(&self) -> Result<(BTreeMap<String, Value>, Vec<Error>)> {
        // Validate field count
        if self.request.fields.len() > MAX_FIELDS {
            bail!(
                "field count {} exceeds maximum {}",
                self.request.fields.len(),
                MAX_FIELDS
            );
        }
        
        let suite: Suite = self.request.suite_id.as_str().try_into()?;
        // ... rest of implementation
    }
}
```

### 5. Private Key Zeroization (kms.rs)

Ensure sensitive key material is zeroized:

```rust
use zeroize::Zeroize;

pub fn get_secret_key(
    alg: &'static EcdsaSigningAlgorithm,
    payload: &EnclaveRequest,
) -> Result<HpkePrivateKey> {
    let mut plaintext_sk = call_kms_decrypt(
        &payload.credential,
        &payload.request.encrypted_private_key,
        &payload.request.region,
    )?;

    // Process key and ensure zeroization on all paths
    let result = (|| -> Result<HpkePrivateKey> {
        let sk = EcdsaKeyPair::from_private_key_der(alg, &plaintext_sk)?;
        let sk_bytes = sk.private_key().as_be_bytes()?;
        Ok(sk_bytes.as_ref().to_vec().into())
    })();

    // Always zeroize the plaintext key material
    plaintext_sk.zeroize();
    
    result
}
```

### 6. Hash Function Renaming (functions.rs)

Rename misleading function names:

```rust
// Renamed from hmac_sha256 - this computes SHA-256 hash, not HMAC
pub fn sha256_hash(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA256, this.as_bytes());
    HEXLOWER.encode(digest.as_ref())
}

pub fn sha384_hash(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA384, this.as_bytes());
    HEXLOWER.encode(digest.as_ref())
}

pub fn sha512_hash(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA512, this.as_bytes());
    HEXLOWER.encode(digest.as_ref())
}
```

Update CEL context registration in expressions.rs:

```rust
// Register with correct names
context.add_function("sha256", functions::sha256_hash);
context.add_function("sha384", functions::sha384_hash);
context.add_function("sha512", functions::sha512_hash);
```

### 7. Graceful Error Handling (main.rs)

Update the main loop to handle errors gracefully:

```rust
fn main() -> Result<()> {
    println!("[enclave] init");

    let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, ENCLAVE_PORT))
        .expect("bind and listen failed");

    println!("[enclave] listening on port {ENCLAVE_PORT}");

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                println!("[enclave error] failed to accept connection: {:?}", e);
                continue;
            }
        };

        if let Err(err) = handle_client(stream) {
            println!("[enclave error] {:?}", err);
        }
    }

    Ok(())
}
```

### 8. Expression Error Logging (main.rs)

Log expression errors instead of silently ignoring:

```rust
let final_fields = match payload.request.expressions {
    Some(expressions) => match execute_expressions(&decrypted_fields, &expressions) {
        Ok(fields) => fields,
        Err(err) => {
            println!("[enclave warning] expression execution failed: {:?}", err);
            decrypted_fields
        }
    },
    None => decrypted_fields,
};
```

### 9. Allocation Optimizations

Replace unnecessary allocations:

```rust
// In main.rs - use serde_json::to_string instead of json!() macro
let payload: String = serde_json::to_string(&response)?;

// In hpke.rs - use Value::String directly
let value = Value::String(string_value);

// In models.rs - use TryFrom<&str> to avoid clone
let suite: Suite = self.request.suite_id.as_str().try_into()?;
```

### 10. Unified Decrypt Loop (models.rs)

Reduce code duplication with a single loop:

```rust
pub fn decrypt_fields(&self) -> Result<(BTreeMap<String, Value>, Vec<Error>)> {
    if self.request.fields.len() > MAX_FIELDS {
        bail!("field count {} exceeds maximum {}", self.request.fields.len(), MAX_FIELDS);
    }

    let suite: Suite = self.request.suite_id.as_str().try_into()?;
    let private_key = self.get_private_key(&suite)?;
    let hpke_suite = suite.get_hpke_suite();
    let info = self.request.vault_id.as_bytes();
    let is_binary = matches!(&self.request.encoding, Some(e) if e == ENCODING_BINARY);
    
    let mut decrypted_fields = BTreeMap::new();
    let mut errors: Vec<Error> = Vec::new();

    for (field, value) in &self.request.fields {
        let encrypted_data = if is_binary {
            EncryptedData::from_binary(value.as_str(), &suite)?
        } else {
            EncryptedData::from_hex(value.as_str())?
        };

        let decrypted = decrypt_value(hpke_suite, &private_key, info, field, encrypted_data)
            .unwrap_or_else(|error| {
                errors.push(error);
                Value::Null
            });
        decrypted_fields.insert(field.to_string(), decrypted);
    }

    Ok((decrypted_fields, errors))
}
```

## Data Models

### Suite Enum

| Variant | Suite ID Bytes | Encapped Key Size | HPKE Suite |
|---------|---------------|-------------------|------------|
| P256 | `[72,80,75,69,0,16,0,1,0,2]` | 65 bytes | DH_KEM_P256_HKDF_SHA256_AES_256 |
| P384 | `[72,80,75,69,0,17,0,2,0,2]` | 97 bytes | DH_KEM_P384_HKDF_SHA384_AES_256 |
| P521 | `[72,80,75,69,0,18,0,3,0,2]` | 133 bytes | DH_KEM_P521_HKDF_SHA512_AES_256 |

### Protocol Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| MAX_MESSAGE_SIZE | 10,485,760 (10 MB) | Prevent memory exhaustion DoS |
| MAX_FIELDS | 1,000 | Prevent field count DoS |
| ENCLAVE_PORT | 5050 | Vsock listener port |

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

Based on the prework analysis, the following properties have been identified as testable through property-based testing:

### Property 1: Suite Enum Correctness

*For any* Suite variant (P256, P384, P521), the encapped_key_size(), get_hpke_suite(), and get_signing_algorithm() methods SHALL return the correct values as defined in the HPKE specification.

**Validates: Requirements 1.1, 9.3**

### Property 2: Binary Parsing with Suite

*For any* valid encrypted data blob and any Suite variant, calling from_binary() with the suite SHALL correctly split the data at the suite's encapped_key_size() offset, producing an EncryptedData with encapped_key of exactly that size and ciphertext containing the remainder.

**Validates: Requirements 1.2**

### Property 3: Message Size Bounds

*For any* message size value greater than MAX_MESSAGE_SIZE, the recv_message() function SHALL return an error without allocating a buffer of that size.

**Validates: Requirements 2.2, 2.3**

### Property 4: Field Count Bounds

*For any* request with field count greater than MAX_FIELDS, the decrypt_fields() function SHALL return an error before attempting to process any fields.

**Validates: Requirements 7.2, 7.3**

### Property 5: Expression Failure Fallback

*For any* set of decrypted fields and any invalid CEL expression, when expression execution fails, the system SHALL return the original decrypted fields unchanged.

**Validates: Requirements 8.2**

### Property 6: Suite Parsing Round-Trip

*For any* valid Suite variant, encoding it to base64 bytes and parsing it back via TryFrom<&str> SHALL produce the same Suite variant.

**Validates: Requirements 9.2, 11.3**

### Property 7: Protocol Message Round-Trip

*For any* valid message string within MAX_MESSAGE_SIZE, sending it via send_message() and receiving it via recv_message() SHALL produce the identical byte sequence.

**Validates: Requirements 16.1**

## Error Handling

### Error Categories

| Category | Handling | Response to Client |
|----------|----------|-------------------|
| Protocol errors | Log and return error | Generic "protocol error" |
| Parse errors | Log and return error | Generic "invalid request" |
| KMS errors | Log and return error | Generic "decryption failed" |
| Field decryption errors | Collect in errors array | Field set to null, error in response |
| Expression errors | Log warning, continue | Return original decrypted fields |
| Connection errors | Log and continue | N/A (connection lost) |

### Error Message Sanitization

External error responses should not leak sensitive information:

```rust
impl EnclaveResponse {
    pub fn error(error: anyhow::Error) -> Self {
        // Log detailed error internally
        println!("[enclave error] {error:?}");
        
        // Return generic message to client
        Self {
            fields: None,
            errors: Some(vec!["request processing failed".to_string()]),
        }
    }
}
```

## Testing Strategy

### Unit Tests

Unit tests verify specific examples and edge cases:

1. **Suite tests**: Verify each variant returns correct values
2. **EncryptedData tests**: Test hex and binary parsing with known values
3. **Protocol tests**: Test message framing with specific sizes
4. **Hash function tests**: Verify renamed functions produce correct digests
5. **Expression tests**: Test CEL function registration and execution

### Property-Based Tests

Property-based tests verify universal properties across generated inputs using the `proptest` crate:

**Configuration**: Minimum 100 iterations per property test

**Test Annotations**: Each test must reference its design property:
```rust
// **Feature: enclave-improvements, Property 1: Suite enum correctness**
// **Validates: Requirements 1.1, 9.3**
#[test]
fn prop_suite_methods_return_correct_values() { ... }
```

### Test Files

| Module | Test Location | Coverage |
|--------|--------------|----------|
| models.rs | `#[cfg(test)] mod tests` | Suite, EncryptedData, field limits |
| protocol.rs | `#[cfg(test)] mod tests` | Message round-trip, size limits |
| functions.rs | `#[cfg(test)] mod tests` | Hash functions |
| expressions.rs | `#[cfg(test)] mod tests` | CEL execution, error fallback |

### Property Test Dependencies

Add to `Cargo.toml` under `[dev-dependencies]`:

```toml
[dev-dependencies]
proptest = "1.4"
```

## Implementation Notes

### Backward Compatibility

The hash function renaming (hmac_sha* → sha*_hash) is a breaking change for existing CEL expressions. Consider:

1. **Option A**: Keep old names as aliases (deprecated)
2. **Option B**: Document migration path, update all expressions

Recommendation: Option B - clean break with documentation.

### Constants Location

New constants should be added to `enclave/src/constants.rs`:

```rust
// Protocol limits
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
pub const MAX_FIELDS: usize = 1000;

// Existing constants remain unchanged
pub const ENCLAVE_PORT: u32 = 5050;
pub const P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
pub const P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
pub const P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];
pub const ENCODING_BINARY: &str = "2";
// Remove ENCODING_HEX if unused, or use it in the default path
```

### Debug Logging

For production builds, sensitive logging should be gated:

```rust
#[cfg(debug_assertions)]
println!("[enclave] vault_id: {:?}", &self.request.vault_id);
```

Or remove entirely and rely on structured error responses.


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Suite Enum Correctness

*For any* Suite variant (P256, P384, P521), the `encapped_key_size()` method SHALL return the correct size (65, 97, 133 bytes respectively), `get_hpke_suite()` SHALL return the corresponding HPKE implementation, and `get_signing_algorithm()` SHALL return the matching ECDSA algorithm.

**Validates: Requirements 1.1, 9.3**

### Property 2: Binary Parsing with Suite

*For any* valid base64-encoded encrypted data and any Suite variant, `EncryptedData::from_binary(data, suite)` SHALL split the data at exactly `suite.encapped_key_size()` bytes, with the first portion as `encapped_key` and the remainder as `ciphertext`.

**Validates: Requirements 1.2**

### Property 3: Message Size Bounds

*For any* message size value greater than `MAX_MESSAGE_SIZE`, the `recv_message()` function SHALL return an error without allocating a buffer of that size.

**Validates: Requirements 2.2, 2.3**

### Property 4: Field Count Bounds

*For any* request with field count greater than `MAX_FIELDS`, the `decrypt_fields()` function SHALL return an error before attempting to decrypt any fields.

**Validates: Requirements 7.2, 7.3**

### Property 5: Expression Failure Fallback

*For any* set of decrypted fields and any expression that fails to execute, the system SHALL return the original decrypted fields unchanged.

**Validates: Requirements 8.2**

### Property 6: Suite Parsing Round-Trip

*For any* valid Suite variant, encoding it to its base64 suite ID and parsing it back SHALL produce the same Suite variant.

**Validates: Requirements 9.2, 11.3**

### Property 7: Protocol Message Round-Trip

*For any* valid message string within size limits, sending it via `send_message()` and receiving it via `recv_message()` SHALL produce the identical byte sequence.

**Validates: Requirements 16.1**

## Error Handling

### Protocol Errors

| Error Condition | Response | Log Level |
|----------------|----------|-----------|
| Message size exceeds MAX_MESSAGE_SIZE | Return error with size details | Error |
| Failed to read message header | Return error | Error |
| Failed to read message body | Return error | Error |
| Failed to write message | Return error | Error |

### Model Errors

| Error Condition | Response | Log Level |
|----------------|----------|-----------|
| Field count exceeds MAX_FIELDS | Return error with counts | Error |
| Invalid suite ID | Return error | Error |
| Encrypted data too short for suite | Return error with size details | Error |
| Invalid hex format (missing '#') | Return error | Error |
| Base64 decode failure | Return error | Error |

### Server Errors

| Error Condition | Response | Log Level |
|----------------|----------|-----------|
| Connection accept failure | Log and continue | Error |
| Client handler failure | Log and continue | Error |
| Expression execution failure | Log warning, return original fields | Warning |
| KMS decrypt failure | Return error to client | Error |
| HPKE decrypt failure | Add to errors list, return Null | Warning |

### Error Message Guidelines

1. **Internal logs**: Include full context (field names, sizes, error details)
2. **Client responses**: Use generic messages without request-specific data
3. **Size errors**: Always include both actual and maximum values

## Testing Strategy

### Property-Based Testing

The implementation will use property-based testing with the `proptest` crate to verify correctness properties. Each property test will run a minimum of 100 iterations.

### Test Configuration

```toml
[dev-dependencies]
proptest = "1.4"
```

### Property Tests

#### Property 1: Suite Enum Correctness
```rust
// Feature: enclave-improvements, Property 1: Suite enum correctness
// Validates: Requirements 1.1, 9.3
proptest! {
    #[test]
    fn prop_suite_encapped_key_sizes(suite in prop::sample::select(vec![Suite::P256, Suite::P384, Suite::P521])) {
        let expected = match suite {
            Suite::P256 => 65,
            Suite::P384 => 97,
            Suite::P521 => 133,
        };
        prop_assert_eq!(suite.encapped_key_size(), expected);
    }
}
```

#### Property 2: Binary Parsing with Suite
```rust
// Feature: enclave-improvements, Property 2: Binary parsing with suite
// Validates: Requirements 1.2
proptest! {
    #[test]
    fn prop_from_binary_splits_at_suite_size(
        suite in prop::sample::select(vec![Suite::P256, Suite::P384, Suite::P521]),
        extra_bytes in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        let key_size = suite.encapped_key_size();
        let mut data = vec![0u8; key_size];
        data.extend(&extra_bytes);
        let b64 = BASE64.encode(&data);
        
        let result = EncryptedData::from_binary(&b64, &suite).unwrap();
        prop_assert_eq!(result.encapped_key.len(), key_size);
        prop_assert_eq!(result.ciphertext.len(), extra_bytes.len());
    }
}
```

#### Property 3: Message Size Bounds
```rust
// Feature: enclave-improvements, Property 3: Message size bounds
// Validates: Requirements 2.2, 2.3
proptest! {
    #[test]
    fn prop_oversized_messages_rejected(size in (MAX_MESSAGE_SIZE + 1)..u64::MAX) {
        // Create mock stream with oversized header
        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, size);
        let mut cursor = Cursor::new(header.to_vec());
        
        let result = recv_message_from_reader(&mut cursor);
        prop_assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        prop_assert!(err_msg.contains(&size.to_string()));
        prop_assert!(err_msg.contains(&MAX_MESSAGE_SIZE.to_string()));
    }
}
```

#### Property 6: Suite Parsing Round-Trip
```rust
// Feature: enclave-improvements, Property 6: Suite parsing round-trip
// Validates: Requirements 9.2, 11.3
proptest! {
    #[test]
    fn prop_suite_roundtrip(suite in prop::sample::select(vec![Suite::P256, Suite::P384, Suite::P521])) {
        let b64 = suite.to_base64();
        let parsed: Suite = b64.as_str().try_into().unwrap();
        prop_assert_eq!(suite, parsed);
    }
}
```

### Unit Tests

Unit tests will cover specific examples and edge cases:

1. **Suite tests**: Verify each variant's methods return expected values
2. **Protocol tests**: Test message round-trip, oversized rejection, truncated handling
3. **Model tests**: Test field count validation, binary parsing edge cases
4. **Expression tests**: Test failure fallback behavior
5. **Hash function tests**: Verify renamed functions produce correct output

### Test Organization

```
enclave/src/
├── models.rs          # Unit tests for Suite, EncryptedData, field limits
├── protocol.rs        # Unit tests for send/recv, property tests for round-trip
├── functions.rs       # Unit tests for renamed hash functions
├── expressions.rs     # Unit tests for failure fallback
└── lib.rs             # Integration property tests
```
