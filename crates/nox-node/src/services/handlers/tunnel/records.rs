//! Streaming check that client bytes are TLS records. Record headers are cleartext, so the
//! exit checks framing without decrypting anything.

use thiserror::Error;

const HEADER_LEN: usize = 5;
/// TLS 1.3 ciphertext limit (2^14 + 256), also above every TLS 1.2 record.
pub const MAX_RECORD_LEN: usize = 16_640;
const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_APPLICATION_DATA: u8 = 23;

/// Legacy record versions TLS 1.2 and 1.3 clients send: 0x0301 on a first `ClientHello`,
/// 0x0303 after.
#[must_use]
pub const fn is_record_version(version: u16) -> bool {
    matches!(version, 0x0301 | 0x0303)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("record content type {0} is not TLS")]
    ContentType(u8),
    #[error("record version 0x{0:04x} is not a TLS record version")]
    Version(u16),
    #[error("record length {0} exceeds {MAX_RECORD_LEN}")]
    Length(usize),
}

/// Follows record boundaries across writes of any size.
#[derive(Debug, Default)]
pub struct RecordFramer {
    header: [u8; HEADER_LEN],
    header_len: usize,
    body_remaining: usize,
}

impl RecordFramer {
    pub fn feed(&mut self, mut data: &[u8]) -> Result<(), RecordError> {
        while !data.is_empty() {
            if self.body_remaining > 0 {
                let take = self.body_remaining.min(data.len());
                self.body_remaining -= take;
                data = &data[take..];
                continue;
            }
            let take = (HEADER_LEN - self.header_len).min(data.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&data[..take]);
            self.header_len += take;
            data = &data[take..];
            if self.header_len == HEADER_LEN {
                self.header_len = 0;
                self.body_remaining = Self::check_header(self.header)?;
            }
        }
        Ok(())
    }

    fn check_header(header: [u8; HEADER_LEN]) -> Result<usize, RecordError> {
        let [content_type, version_high, version_low, length_high, length_low] = header;
        if !(CONTENT_CHANGE_CIPHER_SPEC..=CONTENT_APPLICATION_DATA).contains(&content_type) {
            return Err(RecordError::ContentType(content_type));
        }
        let version = u16::from_be_bytes([version_high, version_low]);
        if !is_record_version(version) {
            return Err(RecordError::Version(version));
        }
        let length = usize::from(u16::from_be_bytes([length_high, length_low]));
        if length > MAX_RECORD_LEN {
            return Err(RecordError::Length(length));
        }
        Ok(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(content_type: u8, version: u16, body_len: usize) -> Vec<u8> {
        let mut record = vec![content_type];
        record.extend_from_slice(&version.to_be_bytes());
        record.extend_from_slice(&(body_len as u16).to_be_bytes());
        record.extend(std::iter::repeat_n(0xab, body_len));
        record
    }

    #[test]
    fn record_framing_holds_across_chunk_boundaries() {
        let mut stream = record(22, 0x0301, 300);
        stream.extend(record(20, 0x0303, 1));
        stream.extend(record(23, 0x0303, MAX_RECORD_LEN));
        stream.extend(record(21, 0x0303, 2));
        for chunk in [1, 2, 4, 5, 7, 4_096, stream.len()] {
            let mut framer = RecordFramer::default();
            for piece in stream.chunks(chunk) {
                assert_eq!(framer.feed(piece), Ok(()), "chunk size {chunk}");
            }
        }

        for (bad, expected) in [
            (record(24, 0x0303, 1), RecordError::ContentType(24)),
            (
                b"GET / HTTP/1.1\r\n".to_vec(),
                RecordError::ContentType(b'G'),
            ),
            (record(23, 0x0302, 1), RecordError::Version(0x0302)),
            (
                record(23, 0x0303, MAX_RECORD_LEN + 1),
                RecordError::Length(MAX_RECORD_LEN + 1),
            ),
        ] {
            let mut framer = RecordFramer::default();
            let mut stream = record(23, 0x0303, 3);
            stream.extend(bad);
            let result = stream.chunks(3).try_for_each(|piece| framer.feed(piece));
            assert_eq!(result, Err(expected));
        }
    }
}
