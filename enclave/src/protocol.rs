// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::{
    io::{Read, Write},
    mem::size_of,
};

use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};
use vsock::VsockStream;

pub fn send_message(stream: &mut VsockStream, msg: String) -> Result<()> {
    // write message length
    let payload_len: u64 = msg
        .len()
        .try_into()
        .map_err(|err| anyhow!("failed to compute message length: {:?}", err))?;
    let mut header_buf = [0; size_of::<u64>()];
    LittleEndian::write_u64(&mut header_buf, payload_len);
    stream
        .write(&header_buf)
        .map_err(|err| anyhow!("failed to write message header: {:?}", err))?;

    // write message body
    let payload_buf = msg.as_bytes();
    stream
        .write_all(payload_buf)
        .map_err(|err| anyhow!("failed to write message body: {:?}", err))?;

    Ok(())
}

pub fn recv_message(stream: &mut VsockStream) -> Result<Vec<u8>> {
    // Buffer to hold the size of the incoming data
    let mut size_buf = [0; size_of::<u64>()];
    stream
        .read_exact(&mut size_buf)
        .map_err(|err| anyhow!("failed to read message header: {:?}", err))?;

    // Convert the size buffer to u64
    let size = LittleEndian::read_u64(&size_buf);

    // Create a buffer of the size we just read
    let mut payload_buffer = vec![0; size as usize];
    stream
        .read_exact(&mut payload_buffer)
        .map_err(|err| anyhow!("failed to read message body: {:?}", err))?;

    Ok(payload_buffer)
}
