# Implementation Plan

- [x] 1. Create FFI module with C library bindings
  - [x] 1.1 Create `enclave/src/aws_ne/ffi.rs` with FFI declarations
    - Define constants: `AWS_NE_VSOCK_PROXY_ADDR`, `AWS_NE_VSOCK_PROXY_PORT`, `AWS_SOCKET_VSOCK_DOMAIN`, `AWS_ADDRESS_MAX_LEN`
    - Define opaque pointer types: `aws_allocator`, `aws_string`, `aws_nitro_enclaves_kms_client`, `aws_nitro_enclaves_kms_client_configuration`
    - Define concrete structs: `aws_byte_buf`, `aws_socket_endpoint`
    - Declare extern "C" functions for SDK lifecycle, string operations, buffer operations, and KMS client
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_
  - [x] 1.2 Write unit test for vsock constants
    - **Property 1: Vsock endpoint constants are correctly defined**
    - **Validates: Requirements 2.4**
  - [x] 1.3 Create `enclave/src/aws_ne/mod.rs` with Error enum and module exports
    - Define `Error` enum with variants: `SdkInitError`, `SdkGenericError`, `SdkKmsConfigError`, `SdkKmsClientError`, `SdkKmsDecryptError`
    - Export `ffi` module
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 2. Implement safe KMS decrypt wrapper
  - [x] 2.1 Implement `kms_decrypt` function in `enclave/src/aws_ne/mod.rs`
    - Initialize SDK with `aws_nitro_enclaves_library_init`
    - Get allocator with `aws_nitro_enclaves_get_allocator`
    - Create aws_string instances for credentials
    - Configure vsock endpoint (CID 3, port 8000)
    - Create KMS client config and client
    - Call `aws_kms_decrypt_blocking`
    - Copy plaintext to Vec<u8>
    - Clean up all resources in reverse order
    - Handle errors at each step with proper cleanup
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 6.1, 6.2, 6.3_

- [x] 3. Update KMS integration to use FFI wrapper
  - [x] 3.1 Modify `enclave/src/kms.rs` to use FFI wrapper
    - Remove `std::process::Command` import
    - Add `use crate::aws_ne` import
    - Update `call_kms_decrypt` to call `aws_ne::kms_decrypt` instead of spawning subprocess
    - Remove "PLAINTEXT: " prefix parsing logic
    - Convert `aws_ne::Error` to `anyhow::Error`
    - _Requirements: 3.1, 3.2, 3.3_
  - [x] 3.2 Write unit test for error conversion
    - **Property 2: Error enum is convertible to anyhow::Error**
    - **Validates: Requirements 3.3**
  - [x] 3.3 Update `enclave/src/lib.rs` to export aws_ne module
    - Add `pub mod aws_ne;` declaration
    - _Requirements: 1.1_

- [x] 4. Update build configuration
  - [x] 4.1 Create `enclave/build.rs` with library linking
    - Add `println!("cargo:rustc-link-lib=dylib=aws-c-common");`
    - Add `println!("cargo:rustc-link-lib=dylib=aws-nitro-enclaves-sdk-c");`
    - _Requirements: 5.1_
  - [x] 4.2 Update `enclave/Cargo.toml` to add libc dependency
    - Add `libc = "0.2"` for c_int, c_void types
    - _Requirements: 1.1_

- [x] 5. Checkpoint - Verify compilation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Update Docker build
  - [x] 6.1 Modify `enclave/Dockerfile` to copy shared libraries instead of CLI binary
    - Remove `COPY --from=kmstool /usr/bin/kmstool_enclave_cli /app/kmstool_enclave_cli`
    - Add COPY commands for required shared libraries from kmstool stage
    - Update `LD_LIBRARY_PATH` if needed
    - _Requirements: 5.2, 5.3_
  - [x] 6.2 Remove kmstool_enclave_cli chmod and references
    - Remove `RUN chmod +x /app/kmstool_enclave_cli`
    - _Requirements: 5.2_

- [x] 7. Clean up old code
  - [x] 7.1 Remove subprocess-related code from `enclave/src/kms.rs`
    - Remove `PLAINTEXT_PREFIX` constant usage if no longer needed
    - Remove any remaining Command-related imports
    - _Requirements: 3.1_

- [x] 8. Final Checkpoint - Verify build and tests
  - Ensure all tests pass, ask the user if questions arise.
