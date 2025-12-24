// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::io::{Read, Write};
use std::thread;

use anyhow::{Error, Result, anyhow};
use enclave_vault::{
    constants::ENCLAVE_PORT,
    expressions::execute_expressions,
    models::{EnclaveRequest, EnclaveResponse},
    protocol::{recv_message, send_message},
};
use vsock::VsockListener;

// Avoid musl's default allocator due to terrible performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[inline]
fn parse_payload(payload_buffer: &[u8]) -> Result<EnclaveRequest> {
    let payload: EnclaveRequest = serde_json::from_slice(payload_buffer)
        .map_err(|err| anyhow!("failed to deserialize payload: {err:?}"))?;
    Ok(payload)
}

#[inline]
fn send_error<W: Write>(mut stream: W, err: Error) -> Result<()> {
    println!("[enclave error] {err:?}");

    let response = EnclaveResponse::error(err);

    let payload: String = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize error response: {err:?}"))?;

    if let Err(err) = send_message(&mut stream, &payload) {
        println!("[enclave error] failed to send error: {err:?}");
    }

    Ok(())
}

fn handle_client<S: Read + Write>(mut stream: S) -> Result<()> {
    println!("[enclave] handling client");

    let payload: EnclaveRequest = match recv_message(&mut stream)
        .map_err(|err| anyhow!("failed to receive message: {err:?}"))
    {
        Ok(payload_buffer) => match parse_payload(&payload_buffer) {
            Ok(payload) => payload,
            Err(err) => return send_error(stream, err),
        },
        Err(err) => return send_error(stream, err),
    };

    // Decrypt the individual field values (uses rayon for parallelization internally)
    let (decrypted_fields, errors) = match payload.decrypt_fields() {
        Ok(result) => result,
        Err(err) => return send_error(stream, err),
    };

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

    let response = EnclaveResponse::new(final_fields, Some(errors));

    let payload: String = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize response: {err:?}"))?;

    println!("[enclave] sending response to parent");

    if let Err(err) = send_message(&mut stream, &payload)
        .map_err(|err| anyhow!("Failed to send message: {err:?}"))
    {
        return send_error(stream, err);
    }

    println!("[enclave] finished client");

    Ok(())
}

fn main() -> Result<()> {
    println!("[enclave] init");

    let listener = match VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, ENCLAVE_PORT) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[enclave fatal] failed to bind listener on port {}: {:?}",
                ENCLAVE_PORT, e
            );
            std::process::exit(1);
        }
    };

    println!("[enclave] listening on port {ENCLAVE_PORT}");

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // Spawn a new thread to handle each client concurrently
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream) {
                        println!("[enclave error] {:?}", err);
                    }
                });
            }
            Err(e) => {
                println!("[enclave error] failed to accept connection: {:?}", e);
                continue;
            }
        }
    }

    Ok(())
}
