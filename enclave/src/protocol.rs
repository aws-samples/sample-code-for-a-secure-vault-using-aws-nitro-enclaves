// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Protocol module for vsock message framing.
//!
//! This module implements a simple length-prefixed message protocol for communication
//! between the parent instance and the Nitro Enclave over vsock. Messages are framed
//! with an 8-byte little-endian length prefix followed by the message payload.
//!
//! # Wire Format
//!
//! ```text
//! +----------------+------------------+
//! | Length (8 bytes) | Payload (N bytes) |
//! | Little-endian u64 |                  |
//! +----------------+------------------+
//! ```
//!
//! # Security
//!
//! - Message size is validated before allocation to prevent memory exhaustion DoS
//! - Maximum message size is 10 MB (configurable via `MAX_MESSAGE_SIZE`)
//! - All writes use `write_all()` to ensure complete transmission

use std::{
    io::{Read, Write},
    mem::size_of,
};

use anyhow::{Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vsock::VsockStream;

use crate::constants::MAX_MESSAGE_SIZE;

/// Sends a length-prefixed message to any writer.
///
/// # Arguments
///
/// * `writer` - Any type implementing `Write`
/// * `msg` - The message string to send
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if writing fails.
///
/// # Wire Format
///
/// Writes an 8-byte little-endian length prefix followed by the message bytes.
pub fn send_message<W: Write>(writer: &mut W, msg: &str) -> Result<()> {
    // write message length
    let payload_len: u64 = msg
        .len()
        .try_into()
        .map_err(|err| anyhow!("failed to compute message length: {:?}", err))?;
    let header_buf = payload_len.to_le_bytes();
    writer
        .write_all(&header_buf)
        .map_err(|err| anyhow!("failed to write message header: {:?}", err))?;

    // write message body
    writer
        .write_all(msg.as_bytes())
        .map_err(|err| anyhow!("failed to write message body: {:?}", err))?;

    Ok(())
}

/// Receives a length-prefixed message from any reader.
///
/// # Arguments
///
/// * `reader` - Any type implementing `Read`
///
/// # Returns
///
/// Returns the message payload as a byte vector, or an error if reading fails
/// or the message size exceeds `MAX_MESSAGE_SIZE`.
///
/// # Security
///
/// Validates message size before allocation to prevent memory exhaustion attacks.
/// Messages larger than `MAX_MESSAGE_SIZE` (10 MB) are rejected.
pub fn recv_message<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    // Buffer to hold the size of the incoming data
    let mut size_buf = [0; size_of::<u64>()];
    reader
        .read_exact(&mut size_buf)
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    // Convert the size buffer to u64 using std method
    let size = u64::from_le_bytes(size_buf);

    // Validate message size before allocation to prevent memory exhaustion DoS
    if size > MAX_MESSAGE_SIZE {
        bail!(
            "message size {} exceeds maximum allowed size {}",
            size,
            MAX_MESSAGE_SIZE
        );
    }

    // Safe conversion from u64 to usize (validated above, MAX_MESSAGE_SIZE fits in usize)
    let size_usize: usize = size
        .try_into()
        .map_err(|_| anyhow!("message size {} too large for platform", size))?;

    // Allocate buffer with error handling to prevent panic on allocation failure
    let mut payload_buffer = Vec::new();
    payload_buffer
        .try_reserve(size_usize)
        .map_err(|_| anyhow!("failed to allocate {} bytes for message", size_usize))?;
    payload_buffer.resize(size_usize, 0);

    reader
        .read_exact(&mut payload_buffer)
        .map_err(|err| anyhow!("failed to read message body: {:?}", err))?;

    Ok(payload_buffer)
}

/// Sends a length-prefixed message over a VsockStream.
///
/// Convenience wrapper around [`send_message`] for vsock communication.
pub fn send_vsock_message(stream: &mut VsockStream, msg: &str) -> Result<()> {
    send_message(stream, msg)
}

/// Receives a length-prefixed message from a VsockStream.
///
/// Convenience wrapper around [`recv_message`] for vsock communication.
pub fn recv_vsock_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    recv_message(stream)
}

/// Sends a length-prefixed message asynchronously.
///
/// # Arguments
///
/// * `writer` - Any type implementing `AsyncWrite + Unpin`
/// * `msg` - The message string to send
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if writing fails.
#[inline]
pub async fn send_message_async<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &str) -> Result<()> {
    // write message length
    let payload_len: u64 = msg
        .len()
        .try_into()
        .map_err(|err| anyhow!("failed to compute message length: {:?}", err))?;
    let header_buf = payload_len.to_le_bytes();
    writer
        .write_all(&header_buf)
        .await
        .map_err(|err| anyhow!("failed to write message header: {:?}", err))?;

    // write message body
    writer
        .write_all(msg.as_bytes())
        .await
        .map_err(|err| anyhow!("failed to write message body: {:?}", err))?;

    Ok(())
}

/// Receives a length-prefixed message asynchronously.
///
/// # Arguments
///
/// * `reader` - Any type implementing `AsyncRead + Unpin`
///
/// # Returns
///
/// Returns the message payload as a byte vector, or an error if reading fails
/// or the message size exceeds `MAX_MESSAGE_SIZE`.
///
/// # Security
///
/// Validates message size before allocation to prevent memory exhaustion attacks.
/// Messages larger than `MAX_MESSAGE_SIZE` (10 MB) are rejected.
#[inline]
pub async fn recv_message_async<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    // Buffer to hold the size of the incoming data
    let mut size_buf = [0; size_of::<u64>()];
    reader
        .read_exact(&mut size_buf)
        .await
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    // Convert the size buffer to u64 using std method
    let size = u64::from_le_bytes(size_buf);

    // Validate message size before allocation to prevent memory exhaustion DoS
    if size > MAX_MESSAGE_SIZE {
        bail!(
            "message size {} exceeds maximum allowed size {}",
            size,
            MAX_MESSAGE_SIZE
        );
    }

    // Safe conversion from u64 to usize (validated above, MAX_MESSAGE_SIZE fits in usize)
    let size_usize: usize = size
        .try_into()
        .map_err(|_| anyhow!("message size {} too large for platform", size))?;

    // Allocate buffer with error handling to prevent panic on allocation failure
    let mut payload_buffer = Vec::new();
    payload_buffer
        .try_reserve(size_usize)
        .map_err(|_| anyhow!("failed to allocate {} bytes for message", size_usize))?;
    payload_buffer.resize(size_usize, 0);

    reader
        .read_exact(&mut payload_buffer)
        .await
        .map_err(|err| anyhow!("failed to read message body: {:?}", err))?;

    Ok(payload_buffer)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    // **Feature: enclave-improvements, Property 3: Message size bounds**
    // **Validates: Requirements 2.2, 2.3**
    //
    // *For any* message size value greater than MAX_MESSAGE_SIZE, the recv_message()
    // function SHALL return an error without allocating a buffer of that size.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // **Feature: enclave-improvements, Property 7: Protocol message round-trip**
        // **Validates: Requirements 16.1**
        //
        // *For any* valid message string within size limits, sending it via send_message()
        // and receiving it via recv_message() SHALL produce the identical byte sequence.
        #[test]
        fn prop_message_round_trip(
            // Generate arbitrary strings of varying lengths (0 to 10KB)
            message in prop::string::string_regex("[\\x00-\\x7F]{0,10000}").unwrap()
        ) {
            // Send message to a buffer
            let mut buffer = Vec::new();
            let send_result = send_message(&mut buffer, &message);
            prop_assert!(
                send_result.is_ok(),
                "send_message should succeed for message of length {}",
                message.len()
            );

            // Receive message from the buffer
            let mut cursor = Cursor::new(buffer);
            let recv_result = recv_message(&mut cursor);
            prop_assert!(
                recv_result.is_ok(),
                "recv_message should succeed for message of length {}",
                message.len()
            );

            let received = recv_result.unwrap();

            // Verify the received bytes match the original message
            prop_assert_eq!(
                received.len(),
                message.len(),
                "Received message length should match original"
            );
            prop_assert_eq!(
                received,
                message.as_bytes(),
                "Received message content should match original"
            );
        }

        #[test]
        fn prop_oversized_messages_rejected(
            // Generate sizes from MAX_MESSAGE_SIZE + 1 up to a reasonable upper bound
            // We use a multiplier to avoid generating extremely large values
            size_offset in 1u64..1_000_000
        ) {
            let size = MAX_MESSAGE_SIZE + size_offset;

            // Create a mock stream with an oversized header using std method
            let header = size.to_le_bytes();
            let mut cursor = Cursor::new(header.to_vec());

            // Attempt to receive - should fail before allocating
            let result = recv_message(&mut cursor);

            prop_assert!(
                result.is_err(),
                "recv_message should reject size {} (max is {})",
                size,
                MAX_MESSAGE_SIZE
            );

            // Verify error message contains both the requested size and maximum
            let err_msg = result.unwrap_err().to_string();
            prop_assert!(
                err_msg.contains(&size.to_string()),
                "Error should contain requested size {}, got: {}",
                size,
                err_msg
            );
            prop_assert!(
                err_msg.contains(&MAX_MESSAGE_SIZE.to_string()),
                "Error should contain max size {}, got: {}",
                MAX_MESSAGE_SIZE,
                err_msg
            );
        }

        #[test]
        fn prop_valid_size_messages_accepted(
            // Generate valid sizes from 0 to MAX_MESSAGE_SIZE
            // We limit to smaller sizes for practical testing
            size in 0u64..10_000
        ) {
            // Create test data of the specified size
            let payload = vec![0xABu8; size as usize];

            // Create a mock stream with header + payload using std method
            let mut data = Vec::new();
            let header = size.to_le_bytes();
            data.extend_from_slice(&header);
            data.extend_from_slice(&payload);

            let mut cursor = Cursor::new(data);

            // Attempt to receive - should succeed
            let result = recv_message(&mut cursor);

            prop_assert!(
                result.is_ok(),
                "recv_message should accept size {} (max is {})",
                size,
                MAX_MESSAGE_SIZE
            );

            let received = result.unwrap();
            prop_assert_eq!(
                received.len(),
                size as usize,
                "Received message should have correct length"
            );
            prop_assert_eq!(
                received,
                payload,
                "Received message content should match"
            );
        }

        #[test]
        fn prop_boundary_size_accepted(
            // Test sizes near the boundary
            offset in 0u64..1000
        ) {
            // Test size at MAX_MESSAGE_SIZE - offset (should be accepted)
            let size = MAX_MESSAGE_SIZE.saturating_sub(offset);

            // We can't actually allocate MAX_MESSAGE_SIZE bytes in a test,
            // so we just verify the size check passes by checking the error type
            let header = size.to_le_bytes();
            // Add minimal payload data (we'll get an EOF error, not a size error)
            let mut cursor = Cursor::new(header.to_vec());

            let result = recv_message(&mut cursor);

            // The error should be about reading the body (EOF), not about size
            if let Err(e) = result {
                let err_msg = e.to_string();
                prop_assert!(
                    !err_msg.contains("exceeds maximum"),
                    "Size {} should not be rejected as too large, got: {}",
                    size,
                    err_msg
                );
            }
        }

        // **Feature: enclave-improvements, Property 10: Checked arithmetic**
        // **Validates: Requirements 24.4, 25.5**
        //
        // *For any* message size value (including values that could overflow on 32-bit platforms),
        // the recv_message() function SHALL never panic due to arithmetic overflow. It should
        // either succeed or return an error.
        #[test]
        fn prop_recv_message_never_panics_on_any_size(
            // Generate any u64 value to test size handling
            size in any::<u64>()
        ) {
            // Create a mock stream with the specified size in header using std method
            let header = size.to_le_bytes();
            let mut cursor = Cursor::new(header.to_vec());

            // This should never panic - it should either succeed or return an error
            let result = recv_message(&mut cursor);

            // For sizes > MAX_MESSAGE_SIZE, should return error
            if size > MAX_MESSAGE_SIZE {
                prop_assert!(
                    result.is_err(),
                    "recv_message should reject size {} (max is {})",
                    size,
                    MAX_MESSAGE_SIZE
                );
            }
            // For sizes <= MAX_MESSAGE_SIZE, will fail with EOF (no body data)
            // but should NOT panic
        }
    }

    #[test]
    fn test_max_message_size_exactly_rejected() {
        // Test that MAX_MESSAGE_SIZE + 1 is rejected
        let size = MAX_MESSAGE_SIZE + 1;
        let header = size.to_le_bytes();
        let mut cursor = Cursor::new(header.to_vec());

        let result = recv_message(&mut cursor);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("exceeds maximum"));
    }

    #[test]
    fn test_max_message_size_exactly_accepted() {
        // Test that MAX_MESSAGE_SIZE is accepted (size check passes)
        let size = MAX_MESSAGE_SIZE;
        let header = size.to_le_bytes();
        let mut cursor = Cursor::new(header.to_vec());

        let result = recv_message(&mut cursor);
        // Should fail with EOF error (not enough data), not size error
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            !err_msg.contains("exceeds maximum"),
            "Should not reject MAX_MESSAGE_SIZE"
        );
    }

    // Unit test for message round-trip (send then receive)
    // _Requirements: 16.1_
    #[test]
    fn test_message_round_trip() {
        let original_message = "Hello, Enclave!";

        // Send message to a buffer
        let mut buffer = Vec::new();
        send_message(&mut buffer, original_message).expect("send_message should succeed");

        // Receive message from the buffer
        let mut cursor = Cursor::new(buffer);
        let received = recv_message(&mut cursor).expect("recv_message should succeed");

        // Verify the received message matches the original
        assert_eq!(
            String::from_utf8(received).unwrap(),
            original_message,
            "Round-trip message should match original"
        );
    }

    #[test]
    fn test_message_round_trip_empty() {
        let original_message = "";

        let mut buffer = Vec::new();
        send_message(&mut buffer, original_message).expect("send_message should succeed");

        let mut cursor = Cursor::new(buffer);
        let received = recv_message(&mut cursor).expect("recv_message should succeed");

        assert_eq!(
            String::from_utf8(received).unwrap(),
            original_message,
            "Empty message round-trip should work"
        );
    }

    #[test]
    fn test_message_round_trip_json() {
        let original_message = r#"{"vault_id":"v_123","fields":{"name":"Bob"}}"#;

        let mut buffer = Vec::new();
        send_message(&mut buffer, original_message).expect("send_message should succeed");

        let mut cursor = Cursor::new(buffer);
        let received = recv_message(&mut cursor).expect("recv_message should succeed");

        assert_eq!(
            String::from_utf8(received).unwrap(),
            original_message,
            "JSON message round-trip should preserve content"
        );
    }

    #[test]
    fn test_message_round_trip_unicode() {
        let original_message = "Hello, 世界! 🔐";

        let mut buffer = Vec::new();
        send_message(&mut buffer, original_message).expect("send_message should succeed");

        let mut cursor = Cursor::new(buffer);
        let received = recv_message(&mut cursor).expect("recv_message should succeed");

        assert_eq!(
            String::from_utf8(received).unwrap(),
            original_message,
            "Unicode message round-trip should preserve content"
        );
    }

    // Unit test for truncated message handling
    // _Requirements: 16.3_
    #[test]
    fn test_truncated_message_header() {
        // Only 4 bytes of header (need 8)
        let truncated_header = vec![0x10, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(truncated_header);

        let result = recv_message(&mut cursor);
        assert!(result.is_err(), "Should fail on truncated header");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed to read message header"),
            "Error should mention header read failure, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_truncated_message_body() {
        // Header says 100 bytes, but only 10 bytes of body provided
        let mut data = Vec::new();
        let header = 100u64.to_le_bytes();
        data.extend_from_slice(&header);
        data.extend_from_slice(&[0xABu8; 10]); // Only 10 bytes instead of 100

        let mut cursor = Cursor::new(data);

        let result = recv_message(&mut cursor);
        assert!(result.is_err(), "Should fail on truncated body");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed to read message body"),
            "Error should mention body read failure, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_truncated_message_empty_body() {
        // Header says 50 bytes, but no body provided
        let header = 50u64.to_le_bytes();
        let mut cursor = Cursor::new(header.to_vec());

        let result = recv_message(&mut cursor);
        assert!(result.is_err(), "Should fail when body is missing");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("failed to read message body"),
            "Error should mention body read failure, got: {}",
            err_msg
        );
    }
}
