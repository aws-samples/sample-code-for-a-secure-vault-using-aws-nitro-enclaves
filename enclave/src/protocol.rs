// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::{io::{Read, Write}, mem::size_of};

use anyhow::{Result, anyhow, bail};
use byteorder::{ByteOrder, LittleEndian};
use vsock::VsockStream;

use crate::constants::MAX_MESSAGE_SIZE;

/// Send a length-prefixed message to any writer.
pub fn send_message<W: Write>(writer: &mut W, msg: &str) -> Result<()> {
    // write message length
    let payload_len: u64 = msg
        .len()
        .try_into()
        .map_err(|err| anyhow!("failed to compute message length: {:?}", err))?;
    let mut header_buf = [0; size_of::<u64>()];
    LittleEndian::write_u64(&mut header_buf, payload_len);
    writer
        .write_all(&header_buf)
        .map_err(|err| anyhow!("failed to write message header: {:?}", err))?;

    // write message body
    writer
        .write_all(msg.as_bytes())
        .map_err(|err| anyhow!("failed to write message body: {:?}", err))?;

    Ok(())
}

/// Receive a length-prefixed message from any reader.
pub fn recv_message<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    // Buffer to hold the size of the incoming data
    let mut size_buf = [0; size_of::<u64>()];
    reader
        .read_exact(&mut size_buf)
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    // Convert the size buffer to u64
    let size = LittleEndian::read_u64(&size_buf);

    // Validate message size before allocation to prevent memory exhaustion DoS
    if size > MAX_MESSAGE_SIZE {
        bail!(
            "message size {} exceeds maximum allowed size {}",
            size,
            MAX_MESSAGE_SIZE
        );
    }

    // Create a buffer of the size we just read
    let mut payload_buffer = vec![0; size as usize];
    reader
        .read_exact(&mut payload_buffer)
        .map_err(|err| anyhow!("failed to read message body: {:?}", err))?;

    Ok(payload_buffer)
}

/// Convenience wrapper for sending messages over VsockStream.
pub fn send_vsock_message(stream: &mut VsockStream, msg: &str) -> Result<()> {
    send_message(stream, msg)
}

/// Convenience wrapper for receiving messages over VsockStream.
pub fn recv_vsock_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    recv_message(stream)
}

#[cfg(test)]
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

        #[test]
        fn prop_oversized_messages_rejected(
            // Generate sizes from MAX_MESSAGE_SIZE + 1 up to a reasonable upper bound
            // We use a multiplier to avoid generating extremely large values
            size_offset in 1u64..1_000_000
        ) {
            let size = MAX_MESSAGE_SIZE + size_offset;

            // Create a mock stream with an oversized header
            let mut header = [0u8; 8];
            LittleEndian::write_u64(&mut header, size);
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

            // Create a mock stream with header + payload
            let mut data = Vec::new();
            let mut header = [0u8; 8];
            LittleEndian::write_u64(&mut header, size);
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
            let mut header = [0u8; 8];
            LittleEndian::write_u64(&mut header, size);
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
    }

    #[test]
    fn test_max_message_size_exactly_rejected() {
        // Test that MAX_MESSAGE_SIZE + 1 is rejected
        let size = MAX_MESSAGE_SIZE + 1;
        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, size);
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
        let mut header = [0u8; 8];
        LittleEndian::write_u64(&mut header, size);
        let mut cursor = Cursor::new(header.to_vec());

        let result = recv_message(&mut cursor);
        // Should fail with EOF error (not enough data), not size error
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(!err_msg.contains("exceeds maximum"), "Should not reject MAX_MESSAGE_SIZE");
    }
}
