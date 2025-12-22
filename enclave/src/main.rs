// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{Error, Result, anyhow};
use enclave_vault::{
    constants::ENCLAVE_PORT,
    expressions::execute_expressions,
    models::{EnclaveRequest, EnclaveResponse},
    protocol::{recv_message, send_message},
};
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

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
fn send_error(mut stream: VsockStream, err: Error) -> Result<()> {
    println!("[enclave error] {err:?}");

    let response = EnclaveResponse::error(err);

    let payload: String = serde_json::json!(response).to_string();

    if let Err(err) = send_message(&mut stream, &payload) {
        println!("[enclave error] failed to send error: {err:?}");
    }

    Ok(())
}

fn handle_client(mut stream: VsockStream) -> Result<()> {
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

    // Decrypt the individual field values
    let (decrypted_fields, errors) = match payload.decrypt_fields() {
        Ok(result) => result,
        Err(err) => return send_error(stream, err),
    };

    let final_fields = match payload.request.expressions {
        Some(expressions) => match execute_expressions(&decrypted_fields, &expressions) {
            Ok(fields) => fields,
            Err(_) => decrypted_fields,
        },
        None => decrypted_fields,
    };

    let response = EnclaveResponse::new(final_fields, Some(errors));

    let payload: String = serde_json::json!(response).to_string();

    println!("[enclave] sending response to parent");

    if let Err(err) =
        send_message(&mut stream, &payload).map_err(|err| anyhow!("Failed to send message: {err:?}"))
    {
        return send_error(stream, err);
    }

    println!("[enclave] finished client");

    Ok(())
}

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

    println!("[enclave] finished");

    Ok(())
}
