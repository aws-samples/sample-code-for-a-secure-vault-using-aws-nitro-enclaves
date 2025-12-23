# Implementation Plan: Enclave Improvements

## Overview

This implementation plan addresses security, reliability, and code quality improvements for the AWS Nitro Enclaves Vault enclave module. Tasks are organized into four phases following the priority order from the ENCLAVE_IMPROVEMENTS.md review.

## Tasks

- [x] 1. Phase 1: Critical Fixes

- [x] 1.1 Convert Suite to type-safe enum in models.rs
  - Replace `Suite(Vec<u8>)` tuple struct with enum variants P256, P384, P521
  - Implement `encapped_key_size()` method returning 65, 97, 133 bytes respectively
  - Implement `get_hpke_suite()` returning the correct HPKE implementation
  - Implement `get_signing_algorithm()` returning the correct ECDSA algorithm
  - Implement `TryFrom<&str>` for parsing base64-encoded suite IDs
  - Update existing `TryFrom<String>` to delegate to `TryFrom<&str>`
  - _Requirements: 1.1, 1.4, 9.1, 9.2, 9.3, 9.4, 11.3_

- [x] 1.2 Write property test for Suite enum correctness
  - **Property 1: Suite enum correctness**
  - **Validates: Requirements 1.1, 9.3**

- [x] 1.3 Update EncryptedData::from_binary() to accept Suite parameter
  - Modify `from_binary()` signature to accept `&Suite` parameter
  - Use `suite.encapped_key_size()` to determine split offset
  - Add validation that data length >= encapped key size
  - Return descriptive error if data too short
  - Update all callers in `decrypt_fields()` to pass suite
  - _Requirements: 1.2, 1.3_

- [x] 1.4 Write property test for binary parsing with suite
  - **Property 2: Binary parsing with suite**
  - **Validates: Requirements 1.2**

- [x] 1.5 Add message size bounds checking in protocol.rs
  - Add `MAX_MESSAGE_SIZE` constant (10 MB = 10 * 1024 * 1024)
  - Validate size in `recv_message()` before allocating buffer
  - Return error with both requested size and maximum if exceeded
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [x] 1.6 Write property test for message size bounds
  - **Property 3: Message size bounds**
  - **Validates: Requirements 2.2, 2.3**

- [x] 1.7 Fix incomplete writes in protocol.rs
  - Change `stream.write(&header_buf)` to `stream.write_all(&header_buf)`
  - Verify `stream.write_all(payload_buf)` is already used for body
  - _Requirements: 4.1, 4.2_

- [x] 1.8 Add graceful stream error handling in main.rs
  - Replace `stream.unwrap()` with match expression
  - Log connection errors and continue accepting new connections
  - _Requirements: 3.1, 3.2, 3.3_

- [x] 1.9 Checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [x] 2. Phase 2: Security Hardening

- [x] 2.1 Add private key zeroization in kms.rs
  - Import `zeroize::Zeroize` trait
  - Wrap key processing in closure to ensure zeroization on all paths
  - Call `plaintext_sk.zeroize()` after extracting key bytes
  - _Requirements: 5.1, 5.3_

- [x] 2.2 Rename hash functions in functions.rs
  - Rename `hmac_sha256` to `sha256_hash`
  - Rename `hmac_sha384` to `sha384_hash`
  - Rename `hmac_sha512` to `sha512_hash`
  - _Requirements: 6.1, 6.2, 6.3_

- [x] 2.3 Update CEL context registration in expressions.rs
  - Change function registration from `hmac_sha*` to `sha*`
  - Register as `sha256`, `sha384`, `sha512` for cleaner API
  - Update existing tests to use new function names
  - _Requirements: 6.4_

- [x] 2.4 Add field count limits in models.rs
  - Add `MAX_FIELDS` constant (1000)
  - Add validation at start of `decrypt_fields()`
  - Return error with actual count and maximum if exceeded
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [x] 2.5 Write property test for field count bounds
  - **Property 4: Field count bounds**
  - **Validates: Requirements 7.2, 7.3**

- [x] 2.6 Checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [ ] 3. Phase 3: Code Quality Improvements

- [x] 3.1 Add expression error logging in main.rs
  - Replace silent `Err(_) => decrypted_fields` with logging
  - Log warning with error details before returning original fields
  - _Requirements: 8.1, 8.2, 8.3_

- [x] 3.2 Write property test for expression failure fallback
  - **Property 5: Expression failure fallback**
  - **Validates: Requirements 8.2**

- [x] 3.3 Remove unnecessary allocations
  - In main.rs: Replace `serde_json::json!(response).to_string()` with `serde_json::to_string(&response)?`
  - In hpke.rs: Replace `serde_json::to_value(string_value)?` with `Value::String(string_value)`
  - In models.rs: Use `self.request.suite_id.as_str().try_into()?` instead of clone
  - _Requirements: 11.1, 11.2_

- [x] 3.4 Reduce code duplication in decrypt_fields()
  - Extract encoding check to boolean flag
  - Use single loop with conditional parsing
  - _Requirements: 12.1, 12.2_

- [x] 3.5 Remove or gate sensitive logging in models.rs
  - Remove or comment out `println!` for vault_id and encoding
  - Consider adding debug feature flag for verbose logging
  - _Requirements: 13.1, 13.2_

- [x] 3.6 Checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [x] 4. Phase 4: Housekeeping

- [x] 4.1 Clean up unused code in constants.rs and utils.rs
  - Either use `ENCODING_HEX` in default path or remove it
  - Move `build_suite_id` to `#[cfg(test)]` module or remove if unused
  - _Requirements: 14.1, 14.2_

- [x] 4.2 Add module documentation
  - Add `//!` module-level docs to hpke.rs
  - Add `//!` module-level docs to kms.rs
  - Add `//!` module-level docs to protocol.rs
  - Add `//!` module-level docs to models.rs
  - Add `///` function docs for public APIs
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

- [x] 4.3 Add protocol module tests
  - Add test for message round-trip (send then receive)
  - Add test for oversized message rejection
  - Add test for truncated message handling
  - _Requirements: 16.1, 16.2, 16.3_

- [x] 4.4 Write property test for protocol round-trip
  - **Property 7: Protocol message round-trip**
  - **Validates: Requirements 16.1**

- [x] 4.5 Write property test for suite parsing round-trip
  - **Property 6: Suite parsing round-trip**
  - **Validates: Requirements 9.2, 11.3**

- [x] 4.6 Add model tests for suite and field validation
  - Add tests for all suite encapped key sizes
  - Add tests for field count validation
  - _Requirements: 16.4, 16.5_

- [x] 4.7 Final checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Run `cargo fmt --check` to verify formatting
  - Ask the user if questions arise

- [x] 5. Phase 5: No-Panic Rust Hardening

- [x] 5.1 Configure Cargo.toml for no-panic builds
  - Add `panic = "abort"` to release profile
  - Add clippy lints for `unwrap_used`, `expect_used`, `indexing_slicing`
  - Configure LTO and strip for minimal binary size
  - _Requirements: 17.3, 17.7, 24.1, 24.5_

- [x] 5.2 Replace .expect() with graceful error handling in main.rs
  - Replace `VsockListener::bind().expect()` with match expression
  - Log fatal error and call `std::process::exit(1)` on bind failure
  - Remove any catch_unwind usage (not needed with no-panic approach)
  - _Requirements: 17.1, 17.2_

- [x] 5.3 Audit and replace all `[]` indexing with `.get()`
  - Search for all slice/array indexing operations
  - Replace with `.get()` and explicit error handling
  - Ensure optimizer can prove bounds where possible
  - _Requirements: 17.4, 25.4, 25.6_

- [x] 5.4 Add checked arithmetic for user-influenced calculations
  - Identify all arithmetic on user-provided values
  - Replace `+`, `-`, `*`, `/` with `checked_add`, `checked_sub`, etc.
  - Return errors on overflow instead of panicking
  - _Requirements: 24.4, 25.5_

- [x] 5.5 Audit and remove all unwrap()/expect() calls
  - Search for all `.unwrap()` and `.expect()` calls
  - Replace with `?` operator or explicit error handling
  - Exception: test code may use unwrap()
  - _Requirements: 17.3, 25.3_

- [x] 5.6 Add comprehensive input validation in models.rs
  - Add `validate()` method to EnclaveRequest
  - Validate vault_id is non-empty
  - Validate region is non-empty and contains valid characters
  - Validate suite_id is non-empty
  - Validate encrypted_private_key is non-empty
  - Call validate() at start of decrypt_fields()
  - _Requirements: 22.1, 22.4, 22.5_

- [x] 5.7 Add safe memory allocation in protocol.rs
  - Use `try_into()` for u64 to usize conversion with error handling
  - Use `try_reserve()` for buffer allocation
  - Return error on allocation failure instead of panicking
  - _Requirements: 19.1, 19.2, 19.3, 23.1_

- [x] 5.8 Verify KMS FFI safety in aws_ne/mod.rs
  - Audit all FFI calls for proper null pointer checks
  - Verify cleanup() is called on all error paths
  - Ensure no unwrap() or expect() on FFI results
  - Add comments documenting safety invariants
  - _Requirements: 21.1, 21.2, 21.3, 21.4_

- [x] 5.9 Remove panic-inducing macros from non-test code
  - Search for `panic!()`, `unreachable!()`, `unimplemented!()`
  - Replace with proper error returns
  - Convert `assert!()` to `debug_assert!()` or error returns
  - _Requirements: 25.1, 25.2_

- [x] 5.10 Write property test for safe indexing
  - **Property 9: Safe indexing**
  - **Validates: Requirements 25.4, 25.6**

- [x] 5.11 Write property test for checked arithmetic
  - **Property 10: Checked arithmetic**
  - **Validates: Requirements 24.4, 25.5**

- [x] 5.12 Add CI check for no-panic verification
  - Add script to verify binary size is small (no panic handler linked)
  - Add clippy check for panic-prone patterns
  - Fail CI if unwrap/expect found in non-test code
  - _Requirements: 24.2_

- [x] 5.13 Checkpoint - Verify no-panic build
  - Run `cargo build --release` and check binary size
  - Run `cargo clippy` with no-panic lints enabled
  - Verify no uses of unwrap() or expect() in non-test code
  - Run `nm` or similar to verify no panic symbols linked
  - Ask the user if questions arise

- [x] 6. Phase 6: Additional Optimizations

- [x] 6.1 Add expression length limit constant in constants.rs
  - Add `MAX_EXPRESSION_LENGTH` constant (10 KB = 10 * 1024)
  - _Requirements: 26.1_

- [x] 6.2 Add expression length validation in expressions.rs
  - Validate each expression length before compilation
  - Return error if expression exceeds MAX_EXPRESSION_LENGTH
  - Include actual length and maximum in error message
  - _Requirements: 26.2, 26.3, 26.4_

- [x] 6.3 Gate expression result logging behind debug builds
  - Wrap `println!("[enclave] expression: ...")` with `#[cfg(debug_assertions)]`
  - Ensure error messages don't include expression input values
  - _Requirements: 27.1, 27.2, 27.3_

- [x] 6.4 Replace byteorder crate with std methods in protocol.rs
  - Replace `LittleEndian::write_u64()` with `u64::to_le_bytes()`
  - Replace `LittleEndian::read_u64()` with `u64::from_le_bytes()`
  - Remove `use byteorder::{ByteOrder, LittleEndian};` import
  - _Requirements: 28.1, 28.3_

- [x] 6.5 Remove byteorder dependency from Cargo.toml
  - Remove `byteorder = { version = "=1.5.0", default-features = false }` from enclave/Cargo.toml
  - _Requirements: 28.2_

- [x] 6.6 Update workspace release profile for aggressive size optimization
  - Change `opt-level = "s"` to `opt-level = "z"` in Cargo.toml
  - Change `lto = "thin"` to `lto = true` in Cargo.toml
  - _Requirements: 29.1, 29.2_

- [x] 6.7 Mark Suite::encapped_key_size() as const fn
  - Add `const` keyword to `encapped_key_size()` method signature
  - Verify constants are usable in const contexts
  - _Requirements: 30.1, 30.2, 30.3_

- [x] 6.8 Add inline hints to critical path functions
  - Add `#[inline]` to `decrypt_value()` in hpke.rs
  - Add `#[inline]` to `base64_decode()` in utils.rs
  - Add `#[inline]` to `Encoding::parse()` in models.rs (if exists)
  - _Requirements: 31.1, 31.2, 31.3_

- [x] 6.10 Implement custom Debug for Credential struct
  - Remove `Debug` from derive macro on Credential struct
  - Add `use std::fmt;` import if not present
  - Implement `fmt::Debug` trait for Credential
  - Redact access_key_id, secret_access_key, and session_token with "[REDACTED]"
  - _Requirements: 32.1, 32.2, 32.3_

- [x] 6.11 Add test for Credential debug redaction
  - Verify Debug output contains "[REDACTED]" for all credential fields
  - Verify actual credential values do not appear in debug output
  - _Requirements: 32.4, 32.5_

- [x] 6.9 Checkpoint - Verify optimizations
  - Run `cargo build --release` and compare binary size (should decrease)
  - Run `cargo test` in enclave directory to verify functionality
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

## Notes

- All tasks including property-based tests are required for comprehensive coverage
- Each phase builds on the previous, with checkpoints to verify stability
- Property tests use the `proptest` crate and should run minimum 100 iterations
- All changes maintain backward compatibility with existing API contracts
- The Suite enum change is the most significant refactor and should be done first
- **No-Panic Rust**: Phase 5 follows the "No-Panic Rust" methodology to eliminate panics at compile time:
  - Prefer eliminating panic sources over catching panics with `catch_unwind`
  - Use `.get()` instead of `[]` for all indexing operations
  - Use checked arithmetic (`checked_add`, etc.) for user-influenced values
  - Enable clippy lints to catch panic-prone patterns
  - Set `panic = "abort"` in release profile to minimize binary size
  - Verify no panic handler is linked by checking binary size (~300KB savings)
- **Phase 6 Optimizations**: Additional improvements for size, security, and performance:
  - Expression length limits prevent resource exhaustion attacks
  - Debug-only logging prevents sensitive data leakage to production logs
  - Replacing `byteorder` with std methods reduces dependencies and attack surface
  - `opt-level = "z"` and full LTO provide more aggressive size optimization
  - `const fn` and `#[inline]` hints improve runtime performance
