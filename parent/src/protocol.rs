// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! vsock message protocol for parent-enclave communication.
//!
//! This module implements a simple length-prefixed message protocol for
//! communicating with Nitro Enclaves over vsock. Each message consists of:
//!
//! 1. An 8-byte little-endian length header
//! 2. The message payload (JSON-encoded)
//!
//! # Wire Format
//!
//! ```text
//! +----------------+------------------+
//! | Length (8 bytes) | Payload (N bytes) |
//! | little-endian    | JSON data        |
//! +----------------+------------------+
//! ```
//!
//! # Size Limits
//!
//! Messages larger than [`MAX_MESSAGE_SIZE`] (10 MB) are rejected to prevent
//! memory exhaustion attacks.

use std::{
    io::{Read, Write},
    mem::size_of,
};

use anyhow::{Result, anyhow};
use byteorder::{ByteOrder, LittleEndian};
use vsock::VsockStream;

use crate::constants::MAX_MESSAGE_SIZE;

/// Sends a message over a vsock stream.
///
/// The message is framed with an 8-byte little-endian length header followed
/// by the UTF-8 encoded payload.
///
/// # Arguments
///
/// * `stream` - The vsock stream to write to
/// * `msg` - The message payload (typically JSON)
///
/// # Errors
///
/// Returns an error if:
/// - The message length exceeds `u64::MAX`
/// - Writing to the stream fails
#[tracing::instrument(skip(stream, msg))]
pub fn send_message(stream: &mut VsockStream, msg: String) -> Result<()> {
    // Write 8-byte little-endian length header
    let payload_len: u64 = msg
        .len()
        .try_into()
        .map_err(|err| anyhow!("failed to compute message length: {:?}", err))?;
    let mut header_buf = [0; size_of::<u64>()];
    LittleEndian::write_u64(&mut header_buf, payload_len);
    stream
        .write_all(&header_buf)
        .map_err(|err| anyhow!("failed to write message header: {:?}", err))?;

    // Write message payload
    let payload_buf = msg.as_bytes();
    stream
        .write_all(payload_buf)
        .map_err(|err| anyhow!("failed to write message body: {:?}", err))?;

    Ok(())
}

/// Receives a message from a vsock stream.
///
/// Reads the 8-byte length header, validates the size, then reads the payload.
///
/// # Arguments
///
/// * `stream` - The vsock stream to read from
///
/// # Returns
///
/// The raw message bytes (typically JSON that needs to be deserialized)
///
/// # Errors
///
/// Returns an error if:
/// - Reading from the stream fails
/// - The message size exceeds [`MAX_MESSAGE_SIZE`]
#[tracing::instrument(skip(stream))]
pub fn recv_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    // Read 8-byte little-endian length header
    let mut size_buf = [0; size_of::<u64>()];
    stream
        .read_exact(&mut size_buf)
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    // Validate message size to prevent memory exhaustion
    let size = LittleEndian::read_u64(&size_buf);
    if size > MAX_MESSAGE_SIZE {
        return Err(anyhow!(
            "message size {} exceeds maximum allowed size {}",
            size,
            MAX_MESSAGE_SIZE
        ));
    }

    // Read message payload
    let mut payload_buffer = vec![0; size as usize];
    stream
        .read_exact(&mut payload_buffer)
        .map_err(|err| anyhow!("failed to read message body: {:?}", err))?;

    Ok(payload_buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Header Encoding Tests ====================

    #[test]
    fn test_length_header_encoding() {
        let len: u64 = 12345;
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, len);
        assert_eq!(LittleEndian::read_u64(&buf), 12345);
    }

    #[test]
    fn test_length_header_zero() {
        let len: u64 = 0;
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, len);
        assert_eq!(LittleEndian::read_u64(&buf), 0);
    }

    #[test]
    fn test_length_header_max_message_size() {
        let len: u64 = MAX_MESSAGE_SIZE;
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, len);
        assert_eq!(LittleEndian::read_u64(&buf), MAX_MESSAGE_SIZE);
    }

    #[test]
    fn test_length_header_little_endian_byte_order() {
        let len: u64 = 0x0102030405060708;
        let mut buf = [0u8; 8];
        LittleEndian::write_u64(&mut buf, len);
        // Little-endian: least significant byte first
        assert_eq!(buf, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    // ==================== Message Size Validation Tests ====================

    #[test]
    fn test_message_size_at_limit() {
        // Create a mock "stream" with a header indicating MAX_MESSAGE_SIZE
        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, MAX_MESSAGE_SIZE);

        // For this test, we just verify the header encodes correctly
        let decoded = LittleEndian::read_u64(&header);
        assert_eq!(decoded, MAX_MESSAGE_SIZE);
        assert!(decoded <= MAX_MESSAGE_SIZE); // Would pass validation
    }

    #[test]
    fn test_message_size_exceeds_limit() {
        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, MAX_MESSAGE_SIZE + 1);

        let decoded = LittleEndian::read_u64(&header);
        assert!(decoded > MAX_MESSAGE_SIZE); // Would fail validation
    }

    // ==================== Protocol Wire Format Tests ====================

    #[test]
    fn test_wire_format_empty_message() {
        // An empty message should have a 0-length header followed by no payload
        let msg = "";
        let expected_header = [0u8; 8]; // 0 in little-endian

        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, msg.len() as u64);
        assert_eq!(header, expected_header);
    }

    #[test]
    fn test_wire_format_small_message() {
        let msg = r#"{"test": true}"#;
        let expected_len = msg.len() as u64;

        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, expected_len);

        // Verify we can reconstruct the length
        assert_eq!(LittleEndian::read_u64(&header), expected_len);
    }

    #[test]
    fn test_wire_format_roundtrip_simulation() {
        // Simulate what would happen in a send/receive cycle
        let original_msg = r#"{"vault_id": "v_123", "data": "encrypted"}"#;

        // "Send" side: create header + payload
        let payload_len = original_msg.len() as u64;
        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, payload_len);
        let payload = original_msg.as_bytes();

        // "Receive" side: read header, validate, read payload
        let received_len = LittleEndian::read_u64(&header);
        assert!(received_len <= MAX_MESSAGE_SIZE);
        assert_eq!(received_len as usize, payload.len());

        let received_msg = std::str::from_utf8(payload).unwrap();
        assert_eq!(received_msg, original_msg);
    }

    // ==================== Error Condition Tests ====================

    #[test]
    fn test_size_of_header() {
        // Verify the header size is exactly 8 bytes
        assert_eq!(size_of::<u64>(), 8);
    }

    #[test]
    fn test_max_message_size_constant() {
        // Verify MAX_MESSAGE_SIZE is 10 MB
        assert_eq!(MAX_MESSAGE_SIZE, 10 * 1024 * 1024);
    }

    // Note: Testing send_message and recv_message directly requires a VsockStream,
    // which cannot be created in a normal test environment. The protocol logic
    // is tested above using the primitive operations (LittleEndian read/write).
    //
    // For full integration testing, see the tests/integration/ directory where
    // we can set up mock enclave communication.
}
