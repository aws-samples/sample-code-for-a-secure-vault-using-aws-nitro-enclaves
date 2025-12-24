// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{Error, Result, anyhow};
use enclave_vault::{
    constants::ENCLAVE_PORT,
    expressions::execute_expressions,
    models::{AttestationRequest, AttestationResponse, EnclaveRequest, EnclaveRequestType, EnclaveResponse},
    nsm,
    protocol::{recv_message, send_message},
    utils::base64_decode,
};
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

// Avoid musl's default allocator due to terrible performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Parse the incoming payload, supporting both new tagged format and legacy format.
///
/// The new format uses a "type" tag to discriminate between request types:
/// - `{"type": "decrypt", ...}` for decrypt requests
/// - `{"type": "attestation", ...}` for attestation requests
///
/// For backward compatibility, payloads without a "type" field are treated
/// as legacy decrypt requests.
#[inline]
fn parse_payload(payload_buffer: &[u8]) -> Result<EnclaveRequestType> {
    // First try to parse as the new tagged format
    if let Ok(request_type) = serde_json::from_slice::<EnclaveRequestType>(payload_buffer) {
        return Ok(request_type);
    }

    // Fall back to legacy format (EnclaveRequest without type tag)
    let legacy_request: EnclaveRequest = serde_json::from_slice(payload_buffer)
        .map_err(|err| anyhow!("failed to deserialize payload: {err:?}"))?;

    Ok(EnclaveRequestType::Decrypt(legacy_request))
}

#[inline]
fn send_error(mut stream: VsockStream, err: Error) -> Result<()> {
    println!("[enclave error] {err:?}");

    let response = EnclaveResponse::error(err);

    let payload: String = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize error response: {err:?}"))?;

    if let Err(err) = send_message(&mut stream, &payload) {
        println!("[enclave error] failed to send error: {err:?}");
    }

    Ok(())
}

/// Handle a decrypt request (existing functionality).
fn handle_decrypt(mut stream: VsockStream, request: EnclaveRequest) -> Result<()> {
    println!("[enclave] handling decrypt request");

    // Decrypt the individual field values
    let (decrypted_fields, errors) = match request.decrypt_fields() {
        Ok(result) => result,
        Err(err) => return send_error(stream, err),
    };

    let final_fields = match request.request.expressions {
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

    println!("[enclave] sending decrypt response to parent");

    if let Err(err) = send_message(&mut stream, &payload)
        .map_err(|err| anyhow!("Failed to send message: {err:?}"))
    {
        return send_error(stream, err);
    }

    println!("[enclave] finished decrypt request");

    Ok(())
}

/// Handle an attestation request.
fn handle_attestation(mut stream: VsockStream, request: AttestationRequest) -> Result<()> {
    println!("[enclave] handling attestation request");

    // Decode nonce from base64
    let nonce = match base64_decode(&request.nonce) {
        Ok(n) => n,
        Err(err) => {
            let response = AttestationResponse::error(format!("invalid nonce base64: {err}"));
            let payload = serde_json::to_string(&response)
                .map_err(|err| anyhow!("failed to serialize response: {err:?}"))?;
            send_message(&mut stream, &payload)?;
            return Ok(());
        }
    };

    // Decode optional user_data from base64
    let user_data = match &request.user_data {
        Some(ud) => match base64_decode(ud) {
            Ok(d) => Some(d),
            Err(err) => {
                let response = AttestationResponse::error(format!("invalid user_data base64: {err}"));
                let payload = serde_json::to_string(&response)
                    .map_err(|err| anyhow!("failed to serialize response: {err:?}"))?;
                send_message(&mut stream, &payload)?;
                return Ok(());
            }
        },
        None => None,
    };

    // Generate attestation document
    let response = match nsm::get_attestation_document(
        user_data.as_deref(),
        Some(&nonce),
        None, // public_key not used for this endpoint
    ) {
        Ok(document) => {
            // Encode document as base64
            let document_b64 = data_encoding::BASE64.encode(&document);
            AttestationResponse::success(document_b64)
        }
        Err(err) => {
            println!("[enclave error] attestation failed: {err:?}");
            AttestationResponse::error(err.to_string())
        }
    };

    let payload = serde_json::to_string(&response)
        .map_err(|err| anyhow!("failed to serialize attestation response: {err:?}"))?;

    println!("[enclave] sending attestation response to parent");

    if let Err(err) = send_message(&mut stream, &payload)
        .map_err(|err| anyhow!("Failed to send message: {err:?}"))
    {
        return send_error(stream, err);
    }

    println!("[enclave] finished attestation request");

    Ok(())
}

fn handle_client(mut stream: VsockStream) -> Result<()> {
    println!("[enclave] handling client");

    let request_type: EnclaveRequestType = match recv_message(&mut stream)
        .map_err(|err| anyhow!("failed to receive message: {err:?}"))
    {
        Ok(payload_buffer) => match parse_payload(&payload_buffer) {
            Ok(request) => request,
            Err(err) => return send_error(stream, err),
        },
        Err(err) => return send_error(stream, err),
    };

    // Dispatch based on request type
    match request_type {
        EnclaveRequestType::Decrypt(request) => handle_decrypt(stream, request),
        EnclaveRequestType::Attestation(request) => handle_attestation(stream, request),
    }
}

fn main() -> Result<()> {
    println!("[enclave] init");

    let listener = match VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, ENCLAVE_PORT)) {
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
