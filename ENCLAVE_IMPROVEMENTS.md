# Enclave Code Improvement Plan

This document consolidates findings from security and Rust engineering reviews of the enclave codebase. The goal is to minimize external dependencies while maintaining a robust security and operational posture.

---

## Executive Summary

The enclave demonstrates solid security practices including credential zeroization, secure FFI cleanup, and pinned dependencies. However, critical vulnerabilities and code quality issues were identified that require remediation.

**Issue Count by Severity:**
- Critical: 2
- High: 4
- Medium: 8
- Low: 5

---

## Critical Priority Issues

### 1. Hardcoded Encapped Key Size in Binary Parsing

**Location:** `src/models.rs:170-184`
**Type:** Correctness Bug / Security

**Issue:** The `EncryptedData::from_binary()` function hardcodes offset 97 for splitting the encapped key from ciphertext. This is only correct for P384 curves.

| Curve | Encapped Key Size |
|-------|------------------|
| P256  | 65 bytes |
| P384  | 97 bytes (current) |
| P521  | 133 bytes |

**Impact:** Binary-encoded encrypted data using P256 or P521 will fail to decrypt correctly.

**Fix:** Pass suite information to `from_binary()` and calculate the correct offset:

```rust
impl Suite {
    pub fn get_encapped_key_size(&self) -> Result<usize> {
        match self.0.as_slice() {
            s if s == P256 => Ok(65),
            s if s == P384 => Ok(97),
            s if s == P521 => Ok(133),
            _ => bail!("unknown suite"),
        }
    }
}

pub fn from_binary(value: &str, suite: &Suite) -> Result<Self> {
    let encapped_key_size = suite.get_encapped_key_size()?;
    let data = base64_decode(value)?;

    if data.len() < encapped_key_size {
        bail!("encrypted data too short for suite");
    }

    Ok(Self {
        encapped_key: data[0..encapped_key_size].to_vec(),
        ciphertext: data[encapped_key_size..].to_vec(),
    })
}
```

---

### 2. Unbounded Message Size - Denial of Service

**Location:** `src/protocol.rs:42-45`
**Type:** Security Vulnerability

**Issue:** The `recv_message` function reads a `u64` size and allocates a buffer without bounds checking. A malicious parent could send a size of `u64::MAX`, causing memory exhaustion.

```rust
// Vulnerable code:
let size = LittleEndian::read_u64(&size_buf);
let mut payload_buffer = vec![0; size as usize];  // No limit!
```

**Fix:** Add maximum message size validation:

```rust
const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

pub fn recv_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    let mut size_buf = [0; size_of::<u64>()];
    stream.read_exact(&mut size_buf)
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    let size = LittleEndian::read_u64(&size_buf);

    if size > MAX_MESSAGE_SIZE {
        return Err(anyhow!("message size {} exceeds maximum {}", size, MAX_MESSAGE_SIZE));
    }

    let mut payload_buffer = vec![0; size as usize];
    // ...
}
```

---

## High Priority Issues

### 3. Missing Zeroization of Private Key Material

**Location:** `src/kms.rs:33-49`, `src/models.rs:59-65`
**Type:** Security - Memory Safety

**Issue:** While `Credential` uses `ZeroizeOnDrop`, the decrypted private key material has exposure points:
- `plaintext_sk: Vec<u8>` from KMS is not zeroized
- `HpkePrivateKey` lacks `ZeroizeOnDrop`

**Fix:** Wrap sensitive key material with zeroization:

```rust
use zeroize::Zeroize;

pub fn get_secret_key(...) -> Result<HpkePrivateKey> {
    let mut plaintext_sk = call_kms_decrypt(...)?;

    let result = (|| {
        let sk = EcdsaKeyPair::from_private_key_der(alg, &plaintext_sk)?;
        let sk_bytes = sk.private_key().as_be_bytes()?;
        Ok(sk_bytes.as_ref().to_vec().into())
    })();

    plaintext_sk.zeroize();  // Always zeroize
    result
}
```

Consider creating a `SecurePrivateKey` newtype:

```rust
#[derive(ZeroizeOnDrop)]
struct SecurePrivateKey(Vec<u8>);
```

---

### 4. Unchecked Stream Error Crashes Server

**Location:** `src/main.rs:93`
**Type:** Reliability

**Issue:** The server panics on connection errors, crashing the entire enclave.

```rust
for stream in listener.incoming() {
    let stream = stream.unwrap();  // PANIC on error!
```

**Fix:**

```rust
for stream in listener.incoming() {
    let stream = match stream {
        Ok(s) => s,
        Err(e) => {
            println!("[enclave error] failed to accept connection: {:?}", e);
            continue;
        }
    };
    // ...
}
```

---

### 5. Incomplete Write Validation

**Location:** `src/protocol.rs:21-23`
**Type:** Correctness Bug

**Issue:** `.write()` may write fewer bytes than provided. Only `.write_all()` guarantees complete writes.

```rust
// Current:
stream.write(&header_buf)?;

// Fixed:
stream.write_all(&header_buf)?;
stream.write_all(&payload_buf)?;
```

---

### 6. Misnamed Hash Functions

**Location:** `src/functions.rs:29-42`
**Type:** Cryptographic API Confusion

**Issue:** Functions named `hmac_sha256`, `hmac_sha384`, `hmac_sha512` compute plain SHA digests, not HMACs. HMAC requires a secret key.

```rust
// Current - misleading name:
pub fn hmac_sha256(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA256, this.as_bytes());  // SHA, not HMAC!
    HEXLOWER.encode(digest.as_ref())
}
```

**Fix Options:**
1. Rename to `sha256`, `sha384`, `sha512`
2. Implement actual HMAC with key parameter using `aws_lc_rs::hmac`

---

## Medium Priority Issues

### 7. Missing Field Count Limits

**Location:** `src/models.rs:68-114`
**Type:** Security - DoS Prevention

**Issue:** No limit on fields per request. An attacker could send millions of fields.

**Fix:**

```rust
const MAX_FIELDS: usize = 1000;

pub fn decrypt_fields(&self) -> Result<...> {
    if self.request.fields.len() > MAX_FIELDS {
        bail!("field count {} exceeds maximum {}",
              self.request.fields.len(), MAX_FIELDS);
    }
    // ...
}
```

---

### 8. Silent Expression Error Swallowing

**Location:** `src/main.rs:59-65`
**Type:** Debugging / Observability

**Issue:** Expression execution errors are silently ignored.

```rust
// Current:
Err(_) => decrypted_fields,  // Silent!

// Fixed:
Err(err) => {
    println!("[enclave warning] expression execution failed: {:?}", err);
    decrypted_fields
}
```

---

### 9. Suite Should Be an Enum

**Location:** `src/models.rs`
**Type:** Type Safety

**Issue:** `Suite` is a tuple struct wrapping `Vec<u8>`, allowing invalid states.

**Fix:** Use an enum for compile-time safety:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    P256,
    P384,
    P521,
}

impl Suite {
    pub fn get_hpke_suite(&self) -> &'static dyn Hpke { ... }
    pub fn get_signing_algorithm(&self) -> &'static EcdsaSigningAlgorithm { ... }
    pub fn encapped_key_size(&self) -> usize { ... }
}
```

---

### 10. Information Leakage in Error Messages

**Location:** `src/main.rs:27`, `src/hpke.rs:29,35`
**Type:** Security

**Issue:** Error messages include field names and context that could aid attackers.

**Recommendation:** Use generic messages for external responses, detailed logs internally.

---

### 11. CEL Expression Security Concerns

**Location:** `src/expressions.rs:50-69`
**Type:** Security

**Issues:**
- No timeout on expression execution
- No limit on expression length
- Expression results logged with println!

**Fixes:**
- Add expression length limits
- Consider gating debug output
- Sanitize error messages

---

### 12. Unnecessary Allocations

**Locations:**
- `src/main.rs:31,69` - `json!()` macro creates intermediate Value
- `src/models.rs:69` - Unnecessary clone of suite_id
- `src/hpke.rs:39` - `to_value()` instead of `Value::String()`

**Fixes:**

```rust
// Instead of:
let payload: String = serde_json::json!(response).to_string();
// Use:
let payload: String = serde_json::to_string(&response)?;

// Instead of:
let suite: Suite = self.request.suite_id.clone().try_into()?;
// Implement TryFrom<&str> and use:
let suite: Suite = self.request.suite_id.as_str().try_into()?;

// Instead of:
serde_json::to_value(string_value)?
// Use:
Value::String(string_value)
```

---

### 13. Code Duplication in decrypt_fields

**Location:** `src/models.rs:81-111`
**Type:** Maintainability

**Issue:** Hex and binary branches are nearly identical.

**Fix:** Refactor to single loop with conditional parsing.

---

### 14. Sensitive Context in Logs

**Location:** `src/models.rs:72,78-79`, `src/expressions.rs`
**Type:** Security

**Issue:** vault_id, encoding, and expression results are logged.

**Recommendation:** Gate verbose logging behind debug flag or remove for production.

---

## Low Priority Issues

### 15. Unused Constant

**Location:** `src/constants.rs:13`

`ENCODING_HEX` is defined but never used. Either use it in the default path or remove.

---

### 16. Unused Utility Function

**Location:** `src/utils.rs:16-24`

`build_suite_id` is only used in tests. Move to `#[cfg(test)]` module or remove.

---

### 17. Missing Documentation

**Locations:** `src/hpke.rs`, `src/kms.rs`, `src/protocol.rs`, `src/models.rs`

Add module-level `//!` documentation and `///` function documentation for public APIs.

---

### 18. Missing Tests

**Modules without tests:**
- `protocol.rs` - Test message round-trip, oversized messages, truncated messages
- `kms.rs` - Difficult to test without mocking, but document constraints
- Integration tests for error handling paths

---

### 19. Redundant Unsafe Blocks

**Location:** `src/aws_ne/mod.rs:94-136`

Inner `unsafe` blocks are redundant inside `unsafe fn`. Remove or add `// SAFETY:` comments.

---

## Dependency Analysis

Current dependencies are well-chosen. Potential optimizations:

| Dependency | Assessment | Action |
|------------|-----------|--------|
| `byteorder` | Tiny, no deps | Could use std `from_le_bytes`/`to_le_bytes` |
| `cel-interpreter` | Largest dep | Required for feature, review for sandboxing |
| Others | Well-suited | No changes needed |

---

## Implementation Priority

### Phase 1: Critical Fixes (Immediate)
1. Fix hardcoded encapped key size (Critical #1)
2. Add message size limits (Critical #2)
3. Handle stream errors gracefully (High #4)
4. Fix incomplete writes (High #5)

### Phase 2: Security Hardening (Short-term)
5. Add zeroization for private keys (High #3)
6. Rename/fix hash functions (High #6)
7. Add field count limits (Medium #7)
8. Review error message content (Medium #10)

### Phase 3: Code Quality (Medium-term)
9. Convert Suite to enum (Medium #9)
10. Fix silent error swallowing (Medium #8)
11. Remove unnecessary allocations (Medium #12)
12. Reduce code duplication (Medium #13)
13. Gate debug logging (Medium #14)

### Phase 4: Housekeeping (Long-term)
14. Remove unused code (Low #15, #16)
15. Add documentation (Low #17)
16. Add missing tests (Low #18)
17. Clean up unsafe blocks (Low #19)

---

## Testing Strategy

After implementing fixes:

1. **Unit Tests:**
   - Protocol message round-trip
   - All suite encapped key sizes
   - Field count validation
   - Expression limits

2. **Integration Tests:**
   - Full decrypt flow for P256, P384, P521
   - Error handling paths
   - DoS resistance (large messages, many fields)

3. **Security Tests:**
   - Verify zeroization with memory inspection tools
   - Fuzz test message parsing
   - Timing analysis on crypto operations

---

## Positive Observations

The codebase already demonstrates good practices:

- Proper use of `ZeroizeOnDrop` for credentials
- Secure FFI cleanup with `aws_*_destroy_secure`
- No credential logging
- Consistent error propagation with `anyhow::Result`
- Clippy compliance with `-D warnings`
- Using Rust Edition 2024
- BTreeMap for deterministic ordering
- mimalloc with secure feature for musl
- Pinned dependencies with security audits
