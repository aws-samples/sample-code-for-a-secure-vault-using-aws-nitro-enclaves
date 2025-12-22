# Implementation Plan: Enclave Improvements

## Overview

This implementation plan addresses security, reliability, and code quality improvements for the AWS Nitro Enclaves Vault enclave module. Tasks are organized into four phases following the priority order from the ENCLAVE_IMPROVEMENTS.md review.

## Tasks

- [ ] 1. Phase 1: Critical Fixes

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

- [-] 1.4 Write property test for binary parsing with suite
  - **Property 2: Binary parsing with suite**
  - **Validates: Requirements 1.2**

- [ ] 1.5 Add message size bounds checking in protocol.rs
  - Add `MAX_MESSAGE_SIZE` constant (10 MB = 10 * 1024 * 1024)
  - Validate size in `recv_message()` before allocating buffer
  - Return error with both requested size and maximum if exceeded
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 1.6 Write property test for message size bounds
  - **Property 3: Message size bounds**
  - **Validates: Requirements 2.2, 2.3**

- [ ] 1.7 Fix incomplete writes in protocol.rs
  - Change `stream.write(&header_buf)` to `stream.write_all(&header_buf)`
  - Verify `stream.write_all(payload_buf)` is already used for body
  - _Requirements: 4.1, 4.2_

- [ ] 1.8 Add graceful stream error handling in main.rs
  - Replace `stream.unwrap()` with match expression
  - Log connection errors and continue accepting new connections
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 1.9 Checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [ ] 2. Phase 2: Security Hardening

- [ ] 2.1 Add private key zeroization in kms.rs
  - Import `zeroize::Zeroize` trait
  - Wrap key processing in closure to ensure zeroization on all paths
  - Call `plaintext_sk.zeroize()` after extracting key bytes
  - _Requirements: 5.1, 5.3_

- [ ] 2.2 Rename hash functions in functions.rs
  - Rename `hmac_sha256` to `sha256_hash`
  - Rename `hmac_sha384` to `sha384_hash`
  - Rename `hmac_sha512` to `sha512_hash`
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 2.3 Update CEL context registration in expressions.rs
  - Change function registration from `hmac_sha*` to `sha*`
  - Register as `sha256`, `sha384`, `sha512` for cleaner API
  - Update existing tests to use new function names
  - _Requirements: 6.4_

- [ ] 2.4 Add field count limits in models.rs
  - Add `MAX_FIELDS` constant (1000)
  - Add validation at start of `decrypt_fields()`
  - Return error with actual count and maximum if exceeded
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 2.5 Write property test for field count bounds
  - **Property 4: Field count bounds**
  - **Validates: Requirements 7.2, 7.3**

- [ ] 2.6 Checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [ ] 3. Phase 3: Code Quality Improvements

- [ ] 3.1 Add expression error logging in main.rs
  - Replace silent `Err(_) => decrypted_fields` with logging
  - Log warning with error details before returning original fields
  - _Requirements: 8.1, 8.2, 8.3_

- [ ] 3.2 Write property test for expression failure fallback
  - **Property 5: Expression failure fallback**
  - **Validates: Requirements 8.2**

- [ ] 3.3 Remove unnecessary allocations
  - In main.rs: Replace `serde_json::json!(response).to_string()` with `serde_json::to_string(&response)?`
  - In hpke.rs: Replace `serde_json::to_value(string_value)?` with `Value::String(string_value)`
  - In models.rs: Use `self.request.suite_id.as_str().try_into()?` instead of clone
  - _Requirements: 11.1, 11.2_

- [ ] 3.4 Reduce code duplication in decrypt_fields()
  - Extract encoding check to boolean flag
  - Use single loop with conditional parsing
  - _Requirements: 12.1, 12.2_

- [ ] 3.5 Remove or gate sensitive logging in models.rs
  - Remove or comment out `println!` for vault_id and encoding
  - Consider adding debug feature flag for verbose logging
  - _Requirements: 13.1, 13.2_

- [ ] 3.6 Checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [ ] 4. Phase 4: Housekeeping

- [ ] 4.1 Clean up unused code in constants.rs and utils.rs
  - Either use `ENCODING_HEX` in default path or remove it
  - Move `build_suite_id` to `#[cfg(test)]` module or remove if unused
  - _Requirements: 14.1, 14.2_

- [ ] 4.2 Add module documentation
  - Add `//!` module-level docs to hpke.rs
  - Add `//!` module-level docs to kms.rs
  - Add `//!` module-level docs to protocol.rs
  - Add `//!` module-level docs to models.rs
  - Add `///` function docs for public APIs
  - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

- [ ] 4.3 Add protocol module tests
  - Add test for message round-trip (send then receive)
  - Add test for oversized message rejection
  - Add test for truncated message handling
  - _Requirements: 16.1, 16.2, 16.3_

- [ ] 4.4 Write property test for protocol round-trip
  - **Property 7: Protocol message round-trip**
  - **Validates: Requirements 16.1**

- [ ] 4.5 Write property test for suite parsing round-trip
  - **Property 6: Suite parsing round-trip**
  - **Validates: Requirements 9.2, 11.3**

- [ ] 4.6 Add model tests for suite and field validation
  - Add tests for all suite encapped key sizes
  - Add tests for field count validation
  - _Requirements: 16.4, 16.5_

- [ ] 4.7 Final checkpoint - Ensure all tests pass
  - Run `cargo test` in enclave directory
  - Run `cargo clippy` to verify no warnings
  - Run `cargo fmt --check` to verify formatting
  - Ask the user if questions arise

## Notes

- All tasks including property-based tests are required for comprehensive coverage
- Each phase builds on the previous, with checkpoints to verify stability
- Property tests use the `proptest` crate and should run minimum 100 iterations
- All changes maintain backward compatibility with existing API contracts
- The Suite enum change is the most significant refactor and should be done first
