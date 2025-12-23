# Requirements Document

## Introduction

This document specifies the requirements for implementing security, reliability, and code quality improvements to the AWS Nitro Enclaves Vault enclave module. The improvements address critical vulnerabilities, security hardening, and code quality issues identified in the ENCLAVE_IMPROVEMENTS.md review document.

## Glossary

- **Enclave**: The isolated Nitro Enclave application that performs secure decryption operations
- **Suite**: An HPKE cipher suite identifier specifying the cryptographic algorithms (KEM, KDF, AEAD)
- **Encapped_Key**: The encapsulated key produced during HPKE encryption, size varies by curve (P256: 65 bytes, P384: 97 bytes, P521: 133 bytes) as defined in RFC 9180
- **VsockStream**: A virtual socket stream for communication between the parent instance and enclave
- **HpkePrivateKey**: The private key used for HPKE decryption operations
- **CEL**: Common Expression Language used for field transformations
- **Zeroization**: The process of securely erasing sensitive data from memory
- **Nenc**: RFC 9180 term for the length in bytes of an encapsulated key produced by a KEM

## Requirements

### Requirement 1: Suite-Aware Encapped Key Size

**User Story:** As a security engineer, I want the binary parsing to correctly handle all supported HPKE curves, so that encrypted data using P256, P384, or P521 curves can be decrypted correctly.

#### Acceptance Criteria

1. THE Suite SHALL provide a get_encapped_key_size() method that returns the RFC 9180 defined Nenc value for each KEM (P256: 65 bytes, P384: 97 bytes, P521: 133 bytes)
2. WHEN parsing binary-encoded encrypted data, THE EncryptedData::from_binary() SHALL accept the Suite as a parameter to determine the correct split offset
3. IF the encrypted data length is less than the encapped key size for the suite, THEN THE Parser SHALL return a descriptive error including the expected and actual sizes
4. WHEN the suite is unknown, THE Suite::get_encapped_key_size() SHALL return an error

### Requirement 2: Message Size Bounds Checking

**User Story:** As a security engineer, I want message sizes to be validated before allocation, so that malicious inputs cannot cause memory exhaustion denial-of-service attacks.

#### Acceptance Criteria

1. THE Protocol SHALL define a maximum message size constant (10 MB)
2. WHEN receiving a message, THE recv_message() function SHALL validate the size before allocating memory
3. IF the message size exceeds the maximum, THEN THE Protocol SHALL return an error without allocating the buffer
4. THE error message SHALL include both the requested size and the maximum allowed size

### Requirement 3: Graceful Stream Error Handling

**User Story:** As a system operator, I want the enclave server to continue operating when individual connections fail, so that transient errors don't crash the entire enclave.

#### Acceptance Criteria

1. WHEN a connection error occurs in the listener loop, THE Server SHALL log the error and continue accepting new connections
2. THE Server SHALL NOT panic or crash on connection errors
3. WHEN a client handler returns an error, THE Server SHALL log the error and continue processing other clients

### Requirement 4: Complete Write Validation

**User Story:** As a developer, I want all protocol writes to be complete, so that partial writes don't cause data corruption.

#### Acceptance Criteria

1. WHEN sending a message header, THE send_message() function SHALL use write_all() to ensure complete writes
2. WHEN sending a message body, THE send_message() function SHALL use write_all() to ensure complete writes

### Requirement 5: Private Key Zeroization

**User Story:** As a security engineer, I want private key material to be securely erased from memory after use, so that sensitive cryptographic material cannot be recovered from memory.

#### Acceptance Criteria

1. WHEN KMS returns decrypted private key material, THE kms module SHALL zeroize the plaintext before returning
2. THE HpkePrivateKey wrapper SHALL implement secure memory handling
3. WHEN an error occurs during key processing, THE kms module SHALL still zeroize any allocated key material

### Requirement 6: Correct Hash Function Naming

**User Story:** As a developer, I want hash function names to accurately reflect their behavior, so that the API is not misleading about cryptographic operations.

#### Acceptance Criteria

1. THE functions module SHALL rename hmac_sha256 to sha256_hash (or implement actual HMAC)
2. THE functions module SHALL rename hmac_sha384 to sha384_hash (or implement actual HMAC)
3. THE functions module SHALL rename hmac_sha512 to sha512_hash (or implement actual HMAC)
4. THE CEL context SHALL register the renamed functions with appropriate names

### Requirement 7: Field Count Limits

**User Story:** As a security engineer, I want field counts to be limited, so that attackers cannot cause resource exhaustion by sending requests with millions of fields.

#### Acceptance Criteria

1. THE Models module SHALL define a maximum field count constant (1000 fields)
2. WHEN decrypting fields, THE decrypt_fields() function SHALL validate the field count before processing
3. IF the field count exceeds the maximum, THEN THE decrypt_fields() function SHALL return an error
4. THE error message SHALL include both the actual count and the maximum allowed

### Requirement 8: Expression Error Logging

**User Story:** As a system operator, I want expression execution errors to be logged, so that I can diagnose issues with CEL expressions.

#### Acceptance Criteria

1. WHEN an expression execution fails, THE Server SHALL log a warning with the error details
2. THE Server SHALL continue processing with the original decrypted fields when expressions fail
3. THE log message SHALL include context about which expression failed

### Requirement 9: Type-Safe Suite Enum

**User Story:** As a developer, I want the Suite type to be an enum, so that invalid suite states are prevented at compile time.

#### Acceptance Criteria

1. THE Suite type SHALL be an enum with variants P256, P384, and P521
2. THE Suite enum SHALL implement TryFrom<String> for parsing base64-encoded suite IDs
3. THE Suite enum SHALL provide methods for get_suite(), get_signing_algorithm(), and get_encapped_key_size()
4. WHEN an invalid suite ID is provided, THE TryFrom implementation SHALL return a descriptive error

### Requirement 10: Reduced Information Leakage

**User Story:** As a security engineer, I want error messages to not leak sensitive information, so that attackers cannot gain insights from error responses.

#### Acceptance Criteria

1. WHEN returning errors to clients, THE Server SHALL use generic error messages
2. THE Server SHALL log detailed error information internally for debugging
3. THE error responses SHALL NOT include field names, vault IDs, or other request-specific data

### Requirement 11: Unnecessary Allocation Removal

**User Story:** As a developer, I want to minimize unnecessary memory allocations, so that the enclave operates efficiently.

#### Acceptance Criteria

1. WHEN serializing responses, THE Server SHALL use serde_json::to_string() instead of json!() macro
2. WHEN converting strings to JSON values, THE hpke module SHALL use Value::String() directly
3. WHEN parsing suite IDs, THE Suite SHALL implement TryFrom<&str> to avoid cloning

### Requirement 12: Code Duplication Reduction

**User Story:** As a developer, I want the decrypt_fields function to have minimal code duplication, so that the code is maintainable.

#### Acceptance Criteria

1. THE decrypt_fields() function SHALL use a single loop for both hex and binary encodings
2. THE encoding-specific parsing SHALL be extracted to a helper function or conditional

### Requirement 13: Debug Logging Control

**User Story:** As a security engineer, I want sensitive context to not be logged in production, so that logs don't contain exploitable information.

#### Acceptance Criteria

1. THE Server SHALL NOT log vault_id, encoding, or expression results in production builds
2. THE logging of sensitive context SHALL be gated behind a debug configuration or removed

### Requirement 14: Unused Code Removal

**User Story:** As a developer, I want unused code to be removed, so that the codebase is clean and maintainable.

#### Acceptance Criteria

1. THE constants module SHALL either use ENCODING_HEX or remove it
2. THE utils module SHALL move build_suite_id to a test module or remove it if unused

### Requirement 15: Documentation Addition

**User Story:** As a developer, I want public APIs to be documented, so that the code is understandable and maintainable.

#### Acceptance Criteria

1. THE hpke module SHALL have module-level documentation
2. THE kms module SHALL have module-level documentation
3. THE protocol module SHALL have module-level documentation
4. THE models module SHALL have module-level documentation
5. Public functions SHALL have documentation comments explaining their purpose and parameters

### Requirement 16: Test Coverage Addition

**User Story:** As a developer, I want comprehensive test coverage, so that changes can be made with confidence.

#### Acceptance Criteria

1. THE protocol module SHALL have tests for message round-trip
2. THE protocol module SHALL have tests for oversized message rejection
3. THE protocol module SHALL have tests for truncated message handling
4. THE models module SHALL have tests for all suite encapped key sizes
5. THE models module SHALL have tests for field count validation

### Requirement 17: No-Panic Rust Implementation

**User Story:** As a system operator, I want the enclave to be built using no-panic Rust patterns, so that panics are eliminated at compile time rather than caught at runtime.

#### Acceptance Criteria

1. THE main() function SHALL NOT use .expect() for the VsockListener bind operation
2. WHEN the VsockListener fails to bind, THE Server SHALL log the error and exit gracefully with an error code
3. THE Enclave crate SHALL enable clippy lints `clippy::unwrap_used` and `clippy::expect_used` as warnings
4. THE Enclave code SHALL replace all array indexing `[]` with `.get()` and explicit error handling
5. THE Enclave code SHALL use checked arithmetic (`checked_add`, `checked_mul`, etc.) where overflow is possible
6. THE Server MAY use std::panic::catch_unwind() as defense-in-depth but SHALL NOT rely on it as the primary panic prevention strategy
7. THE Enclave build SHALL use `panic = "abort"` in release profile to minimize code size

### Requirement 18: Robust JSON Serialization

**User Story:** As a security engineer, I want JSON serialization to never panic, so that malformed response data cannot crash the enclave.

#### Acceptance Criteria

1. WHEN serializing EnclaveResponse, THE Server SHALL handle serialization errors gracefully
2. IF serde_json::to_string() fails, THEN THE Server SHALL log the error and send a minimal error response
3. THE Server SHALL NOT panic on JSON serialization failures

### Requirement 19: Safe Integer Conversions

**User Story:** As a security engineer, I want integer conversions to be checked, so that overflow cannot cause crashes or undefined behavior.

#### Acceptance Criteria

1. WHEN converting message length to u64, THE Protocol SHALL use checked conversion with try_into()
2. IF the conversion fails, THEN THE Protocol SHALL return an error instead of panicking
3. WHEN converting u64 size to usize for allocation, THE Protocol SHALL validate the conversion is safe

### Requirement 20: Expression Execution Safety

**User Story:** As a security engineer, I want CEL expression execution to be safe, so that malicious expressions cannot crash the enclave.

#### Acceptance Criteria

1. WHEN executing CEL expressions, THE Expressions module SHALL handle all errors via Result
2. IF a CEL expression returns an error, THEN THE Server SHALL return the original decrypted fields
3. THE Server SHALL log a warning when expression execution fails
4. THE CEL execution SHALL NOT use any panicking APIs internally

### Requirement 21: KMS FFI Safety

**User Story:** As a security engineer, I want KMS FFI calls to be robust, so that FFI errors cannot crash the enclave.

#### Acceptance Criteria

1. THE aws_ne module SHALL handle all FFI error codes without panicking
2. WHEN FFI functions return null pointers, THE aws_ne module SHALL return appropriate errors
3. THE aws_ne module SHALL clean up all allocated resources on both success and error paths
4. THE aws_ne module SHALL NOT use unwrap() or expect() on FFI results

### Requirement 22: Input Validation Completeness

**User Story:** As a security engineer, I want all inputs to be validated before processing, so that malformed inputs cannot cause crashes.

#### Acceptance Criteria

1. WHEN parsing EnclaveRequest, THE Parser SHALL validate all required fields are present
2. WHEN parsing EncryptedData from hex, THE Parser SHALL validate the '#' separator exists
3. WHEN parsing base64 data, THE Parser SHALL handle invalid base64 gracefully
4. THE Parser SHALL validate that vault_id is non-empty
5. THE Parser SHALL validate that region is non-empty and contains only valid characters

### Requirement 23: Memory Allocation Safety

**User Story:** As a security engineer, I want memory allocations to be bounded, so that allocation failures cannot crash the enclave.

#### Acceptance Criteria

1. WHEN allocating buffers for received messages, THE Protocol SHALL use try_reserve() or handle allocation failures
2. WHEN creating BTreeMap entries, THE Models module SHALL limit the total size of decrypted data
3. THE Server SHALL define a maximum total response size constant
4. IF total response size would exceed the maximum, THEN THE Server SHALL return an error

### Requirement 24: Compile-Time Panic Prevention

**User Story:** As a developer, I want panic-prone code patterns to be caught at compile time, so that panics cannot be introduced accidentally.

#### Acceptance Criteria

1. THE Enclave Cargo.toml SHALL configure clippy to warn on `unwrap_used` and `expect_used`
2. THE CI pipeline SHALL fail if any `unwrap()` or `expect()` calls are added to non-test code
3. THE Enclave code SHALL use `.get()` with explicit error handling instead of `[]` indexing
4. THE Enclave code SHALL use checked arithmetic for any user-influenced calculations
5. THE Enclave release profile SHALL set `panic = "abort"` to eliminate unwinding overhead

### Requirement 25: Panic Source Elimination

**User Story:** As a security engineer, I want all potential panic sources to be eliminated, so that the enclave binary does not include panic handling code.

#### Acceptance Criteria

1. THE Enclave code SHALL NOT use `panic!()`, `unreachable!()`, or `unimplemented!()` macros
2. THE Enclave code SHALL NOT use `assert!()` in non-test code (use `debug_assert!()` or return errors)
3. THE Enclave code SHALL NOT use `unwrap()` or `expect()` on Option or Result types
4. THE Enclave code SHALL NOT use slice indexing `[]` that could panic on out-of-bounds
5. THE Enclave code SHALL NOT use integer division without checking for zero divisor
6. WHEN the optimizer cannot prove bounds are safe, THE code SHALL use `.get()` with explicit error handling

### Requirement 26: Expression Length Limits

**User Story:** As a security engineer, I want CEL expression lengths to be limited, so that attackers cannot cause resource exhaustion with extremely long expressions.

#### Acceptance Criteria

1. THE Constants module SHALL define a maximum expression length constant (10 KB)
2. WHEN executing expressions, THE execute_expressions() function SHALL validate each expression length before compilation
3. IF an expression exceeds the maximum length, THEN THE function SHALL return an error
4. THE error message SHALL include both the actual length and the maximum allowed

### Requirement 27: Expression Result Sanitization

**User Story:** As a security engineer, I want expression results to not be logged in production, so that sensitive decrypted data cannot leak to logs.

#### Acceptance Criteria

1. THE expressions module SHALL NOT log expression results in production builds
2. THE logging of expression results SHALL be gated behind debug builds only
3. WHEN an expression fails, THE error message SHALL NOT include the expression input values

### Requirement 28: Dependency Reduction

**User Story:** As a developer, I want to minimize external dependencies, so that the attack surface and binary size are reduced.

#### Acceptance Criteria

1. THE protocol module SHALL use std `from_le_bytes()` and `to_le_bytes()` instead of the byteorder crate
2. THE Cargo.toml SHALL remove the byteorder dependency after migration
3. THE protocol module SHALL maintain identical wire format behavior after migration

### Requirement 29: Aggressive Size Optimization

**User Story:** As a system operator, I want the enclave binary to be as small as possible, so that it loads faster and uses less memory.

#### Acceptance Criteria

1. THE workspace Cargo.toml release profile SHALL use `opt-level = "z"` for maximum size reduction
2. THE release profile SHALL use `lto = true` (full LTO) instead of `lto = "thin"`
3. THE enclave binary size SHALL be verified to decrease after optimization changes

### Requirement 30: Const Function Optimization

**User Story:** As a developer, I want compile-time evaluation where possible, so that runtime overhead is minimized.

#### Acceptance Criteria

1. THE Suite::encapped_key_size() method SHALL be marked as `const fn`
2. THE MAX_MESSAGE_SIZE, MAX_FIELDS, and other limit constants SHALL be usable in const contexts
3. THE compiler SHALL be able to evaluate suite key sizes at compile time

### Requirement 31: Inline Hints for Critical Paths

**User Story:** As a developer, I want critical path functions to be inlined, so that function call overhead is eliminated.

#### Acceptance Criteria

1. THE decrypt_value() function in hpke.rs SHALL have `#[inline]` attribute
2. THE base64_decode() function in utils.rs SHALL have `#[inline]` attribute
3. THE Encoding::parse() method SHALL have `#[inline]` attribute

### Requirement 32: Credential Debug Redaction

**User Story:** As a security engineer, I want credential fields to be redacted in debug output, so that sensitive AWS credentials cannot leak to logs or error responses.

#### Acceptance Criteria

1. THE Credential struct SHALL implement a custom Debug trait that redacts all sensitive fields
2. WHEN Debug formatting is applied to Credential, THE output SHALL show "[REDACTED]" for access_key_id, secret_access_key, and session_token
3. THE Credential struct SHALL NOT derive Debug automatically
4. THE EnclaveRequest struct's Debug output SHALL NOT expose credential values
5. WHEN an error occurs during request processing, THE error message SHALL NOT include credential values
