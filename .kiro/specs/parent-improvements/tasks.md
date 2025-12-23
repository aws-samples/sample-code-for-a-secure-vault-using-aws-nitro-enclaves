# Implementation Plan: Parent Improvements

## Overview

This implementation plan addresses security, reliability, and code quality improvements for the AWS Nitro Enclaves Vault parent module. Tasks mirror those applied to the enclave module, focusing on no-panic Rust patterns, dependency reduction, and code optimization.

## Tasks

- [x] 1. Phase 1: Workspace Configuration

- [x] 1.1 Move clippy lints to workspace level
  - Add `[workspace.lints.clippy]` section to root Cargo.toml
  - Configure `unwrap_used`, `expect_used`, `indexing_slicing` as warnings
  - Update enclave/Cargo.toml to inherit from workspace with `[lints] workspace = true`
  - Update parent/Cargo.toml to inherit from workspace with `[lints] workspace = true`
  - _Requirements: 3.1_

- [x] 1.2 Checkpoint - Verify workspace lints
  - Run `cargo clippy` on both enclave and parent
  - Verify lints are applied to both crates
  - Ask the user if questions arise

- [x] 2. Phase 2: Protocol Module Updates

- [x] 2.1 Replace byteorder with std methods in protocol.rs
  - Replace `LittleEndian::write_u64()` with `u64::to_le_bytes()`
  - Replace `LittleEndian::read_u64()` with `u64::from_le_bytes()`
  - Remove `use byteorder::{ByteOrder, LittleEndian};` import
  - _Requirements: 1.1, 1.3_

- [x] 2.2 Add safe memory allocation in recv_message()
  - Use `try_into()` for u64 to usize conversion with error handling
  - Use `try_reserve()` for buffer allocation
  - Return error on allocation failure instead of panicking
  - _Requirements: 2.1, 2.2, 2.3_

- [x] 2.3 Add inline hints to protocol functions
  - Add `#[inline]` to `send_message()` function
  - Add `#[inline]` to `recv_message()` function
  - _Requirements: 7.1, 7.2_

- [x] 2.4 Update protocol tests to use std methods
  - Replace all `LittleEndian::write_u64()` with `to_le_bytes()` in tests
  - Replace all `LittleEndian::read_u64()` with `from_le_bytes()` in tests
  - _Requirements: 1.3_

- [x] 2.5 Remove byteorder dependency from Cargo.toml
  - Remove `byteorder = { version = "=1.5.0", default-features = false }` from parent/Cargo.toml
  - _Requirements: 1.2_

- [x] 2.6 Checkpoint - Verify protocol changes
  - Run `cargo test` in parent directory
  - Run `cargo clippy` to verify no warnings
  - Ask the user if questions arise

- [x] 3. Phase 3: Safe Indexing and Error Handling

- [x] 3.1 Fix unsafe enclave indexing in routes.rs
  - Replace `enclaves[index]` with `enclaves.get(index).ok_or(AppError::EnclaveNotFound)?`
  - Ensure error is returned if enclave list becomes empty between check and access
  - _Requirements: 9.1, 9.2_

- [x] 3.2 Audit main.rs for panic-prone patterns
  - Review all `.unwrap()` and `.expect()` calls
  - Replace with proper error handling where needed
  - Note: `unwrap_or_else` is acceptable as it provides defaults
  - _Requirements: 3.4, 8.1, 8.2, 8.3_

- [x] 3.3 Audit enclaves.rs for panic-prone patterns
  - Review all slice indexing operations
  - Replace with `.get()` where bounds cannot be proven
  - _Requirements: 4.1, 4.3_

- [x] 3.4 Checkpoint - Verify no-panic patterns
  - Run `cargo clippy` to check for warnings
  - Run `cargo test` to verify functionality
  - Ask the user if questions arise

- [x] 4. Phase 4: Property-Based Tests

- [x] 4.1 Add property test for protocol length encoding
  - **Property 1: Protocol message round-trip**
  - Test that `to_le_bytes()` and `from_le_bytes()` are inverses
  - **Validates: Requirements 1.3**

- [x] 4.2 Add property test for message size bounds
  - **Property 2: Message size bounds**
  - Test that oversized messages are rejected without allocation
  - **Validates: Requirements 2.1, 2.2**

- [x] 4.3 Checkpoint - Verify property tests
  - Run `cargo test` in parent directory
  - Verify all property tests pass with 100+ iterations
  - Ask the user if questions arise

- [x] 5. Phase 5: Final Verification

- [x] 5.1 Run full test suite
  - Run `cargo test` in parent directory
  - Run `cargo clippy` to verify no warnings
  - Run `cargo fmt --check` to verify formatting
  - _Requirements: All_

- [x] 5.2 Verify release build
  - Run `cargo build --release` for parent
  - Verify binary compiles without errors
  - _Requirements: All_

- [x] 5.3 Final checkpoint
  - Ensure all tests pass
  - Ensure no clippy warnings
  - Ask the user if questions arise

## Notes

- All tasks including property-based tests are required for comprehensive coverage
- Each phase builds on the previous, with checkpoints to verify stability
- Property tests use the `proptest` crate and should run minimum 100 iterations
- All changes maintain backward compatibility with existing wire protocol
- The parent uses Tokio async runtime, so some patterns differ from the synchronous enclave
- Workspace-level lints ensure consistency between enclave and parent crates
