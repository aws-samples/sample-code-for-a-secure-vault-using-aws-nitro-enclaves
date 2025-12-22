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
