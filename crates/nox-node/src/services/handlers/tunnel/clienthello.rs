//! Checks on the first bytes of a tunnel, done without any key: a `ClientHello` for the
//! requested host that offers only HTTP/1.1 and carries no resumption or early data.

use thiserror::Error;

const RECORD_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const SNI_HOST_NAME: u8 = 0;
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
/// Largest `ClientHello` accepted, records included. Post-quantum key shares add about 1.2 KB.
const MAX_CLIENT_HELLO_LEN: usize = 32 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientHelloError {
    #[error("record content type {0} is not a handshake")]
    NotHandshake(u8),
    #[error("record version 0x{0:04x} is not a TLS record version")]
    BadRecordVersion(u16),
    #[error("record length {0} is outside 1..={max}", max = super::records::MAX_RECORD_LEN)]
    BadRecordLength(usize),
    #[error("handshake message type {0} is not ClientHello")]
    NotClientHello(u8),
    #[error("ClientHello of {0} bytes exceeds {MAX_CLIENT_HELLO_LEN}")]
    TooLong(usize),
    #[error("ClientHello incomplete ({have} of {needed} bytes)")]
    Incomplete { needed: usize, have: usize },
    #[error("ClientHello malformed at {0}")]
    Malformed(&'static str),
    #[error("ClientHello has no server name")]
    MissingSni,
    #[error("ClientHello server name does not match the tunnel host")]
    SniMismatch,
    #[error("ClientHello ALPN must be exactly http/1.1")]
    Alpn,
    #[error("ClientHello offers early data")]
    EarlyData,
    #[error("ClientHello offers a pre-shared key")]
    PreSharedKey,
    #[error("ClientHello offers a session ticket")]
    SessionTicket,
}

impl ClientHelloError {
    /// The server name is the destination check; everything else is a protocol failure.
    #[must_use]
    pub const fn is_host_mismatch(&self) -> bool {
        matches!(self, Self::MissingSni | Self::SniMismatch)
    }
}

#[derive(Debug, Default)]
struct Summary {
    server_name: Option<String>,
    alpn: Option<Vec<Vec<u8>>>,
    offers_psk: bool,
    offers_early_data: bool,
    offers_ticket: bool,
}

/// Accepts `data` when it starts with a complete `ClientHello` whose server name equals
/// `host` (ASCII case-insensitive), whose ALPN list is exactly `http/1.1`, and which offers
/// no early data, no pre-shared key and no TLS 1.2 session ticket.
pub fn check_client_hello(data: &[u8], host: &str) -> Result<(), ClientHelloError> {
    let summary = parse(data)?;
    let server_name = summary.server_name.ok_or(ClientHelloError::MissingSni)?;
    if !server_name.eq_ignore_ascii_case(host) {
        return Err(ClientHelloError::SniMismatch);
    }
    match summary.alpn.as_deref() {
        Some([only]) if only == ALPN_HTTP_1_1 => {}
        _ => return Err(ClientHelloError::Alpn),
    }
    if summary.offers_early_data {
        return Err(ClientHelloError::EarlyData);
    }
    if summary.offers_psk {
        return Err(ClientHelloError::PreSharedKey);
    }
    if summary.offers_ticket {
        return Err(ClientHelloError::SessionTicket);
    }
    Ok(())
}

/// Joins the handshake records at the start of `data` until one `ClientHello` is complete.
fn parse(data: &[u8]) -> Result<Summary, ClientHelloError> {
    let mut handshake = Vec::new();
    let mut offset = 0usize;
    let mut needed: Option<usize> = None;
    loop {
        let header = data
            .get(offset..offset + 5)
            .ok_or(ClientHelloError::Incomplete {
                needed: offset + 5,
                have: data.len(),
            })?;
        let [content_type, version_high, version_low, length_high, length_low] = header else {
            return Err(ClientHelloError::Malformed("record header"));
        };
        if *content_type != RECORD_HANDSHAKE {
            return Err(ClientHelloError::NotHandshake(*content_type));
        }
        let version = u16::from_be_bytes([*version_high, *version_low]);
        if !super::records::is_record_version(version) {
            return Err(ClientHelloError::BadRecordVersion(version));
        }
        let length = usize::from(u16::from_be_bytes([*length_high, *length_low]));
        if length == 0 || length > super::records::MAX_RECORD_LEN {
            return Err(ClientHelloError::BadRecordLength(length));
        }
        let body =
            data.get(offset + 5..offset + 5 + length)
                .ok_or(ClientHelloError::Incomplete {
                    needed: offset + 5 + length,
                    have: data.len(),
                })?;
        handshake.extend_from_slice(body);
        offset += 5 + length;

        if needed.is_none() {
            if let [message_type, a, b, c, ..] = handshake.as_slice() {
                if *message_type != HANDSHAKE_CLIENT_HELLO {
                    return Err(ClientHelloError::NotClientHello(*message_type));
                }
                let message_len =
                    (usize::from(*a) << 16) | (usize::from(*b) << 8) | usize::from(*c);
                if message_len + 4 > MAX_CLIENT_HELLO_LEN {
                    return Err(ClientHelloError::TooLong(message_len + 4));
                }
                needed = Some(message_len + 4);
            }
        }
        if let Some(total) = needed {
            if let Some(message) = handshake.get(4..total) {
                return parse_body(message);
            }
        }
        if handshake.len() > MAX_CLIENT_HELLO_LEN {
            return Err(ClientHelloError::TooLong(handshake.len()));
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize, at: &'static str) -> Result<&'a [u8], ClientHelloError> {
        let slice = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or(ClientHelloError::Malformed(at))?;
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, ClientHelloError> {
        match self.take(1, at)? {
            [byte] => Ok(*byte),
            _ => Err(ClientHelloError::Malformed(at)),
        }
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, ClientHelloError> {
        match self.take(2, at)? {
            [high, low] => Ok(u16::from_be_bytes([*high, *low])),
            _ => Err(ClientHelloError::Malformed(at)),
        }
    }

    fn vec8(&mut self, at: &'static str) -> Result<&'a [u8], ClientHelloError> {
        let n = usize::from(self.u8(at)?);
        self.take(n, at)
    }

    fn vec16(&mut self, at: &'static str) -> Result<&'a [u8], ClientHelloError> {
        let n = usize::from(self.u16(at)?);
        self.take(n, at)
    }

    const fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

fn parse_body(body: &[u8]) -> Result<Summary, ClientHelloError> {
    let mut reader = Reader::new(body);
    reader.take(2, "legacy_version")?;
    reader.take(32, "random")?;
    reader.vec8("legacy_session_id")?;
    let suites = reader.vec16("cipher_suites")?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(ClientHelloError::Malformed("cipher_suites"));
    }
    reader.vec8("compression_methods")?;
    let mut summary = Summary::default();
    if reader.done() {
        return Ok(summary);
    }
    let extensions = reader.vec16("extensions")?;
    if !reader.done() {
        return Err(ClientHelloError::Malformed("trailing bytes"));
    }
    let mut extensions = Reader::new(extensions);
    while !extensions.done() {
        let kind = extensions.u16("extension type")?;
        let data = extensions.vec16("extension body")?;
        match kind {
            EXT_SERVER_NAME => summary.server_name = parse_server_name(data)?,
            EXT_ALPN => summary.alpn = Some(parse_alpn(data)?),
            EXT_PRE_SHARED_KEY => summary.offers_psk = true,
            EXT_EARLY_DATA => summary.offers_early_data = true,
            EXT_SESSION_TICKET => summary.offers_ticket |= !data.is_empty(),
            _ => {}
        }
    }
    Ok(summary)
}

fn parse_server_name(data: &[u8]) -> Result<Option<String>, ClientHelloError> {
    let mut reader = Reader::new(data);
    let mut entries = Reader::new(reader.vec16("server_name_list")?);
    while !entries.done() {
        let name_type = entries.u8("server_name type")?;
        let name = entries.vec16("server_name")?;
        if name_type == SNI_HOST_NAME {
            let host = std::str::from_utf8(name)
                .map_err(|_| ClientHelloError::Malformed("server_name encoding"))?;
            if host.is_empty() || !host.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(ClientHelloError::Malformed("server_name characters"));
            }
            return Ok(Some(host.to_string()));
        }
    }
    Ok(None)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, ClientHelloError> {
    let mut reader = Reader::new(data);
    let mut names = Reader::new(reader.vec16("alpn list")?);
    let mut protocols = Vec::new();
    while !names.done() {
        protocols.push(names.vec8("alpn name")?.to_vec());
    }
    Ok(protocols)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worker's `ClientHello` for `rpc.example`: the output of
    /// `cargo run -p nox-tls --example client_hello` in hisoka-io/nox-sdk (rustls 0.23.45).
    const WORKER_CLIENT_HELLO: &str = include_str!("worker_client_hello.hex");
    const WORKER_HOST: &str = "rpc.example";

    fn worker_hello() -> Vec<u8> {
        hex::decode(WORKER_CLIENT_HELLO.trim()).expect("fixture is hex")
    }

    fn hello_with(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        let mut encoded = Vec::new();
        for (kind, data) in extensions {
            encoded.extend_from_slice(&kind.to_be_bytes());
            encoded.extend_from_slice(&(data.len() as u16).to_be_bytes());
            encoded.extend_from_slice(data);
        }
        body.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        body.extend_from_slice(&encoded);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![RECORD_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn sni(host: &str) -> (u16, Vec<u8>) {
        let mut entry = vec![SNI_HOST_NAME];
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host.as_bytes());
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&entry);
        (EXT_SERVER_NAME, data)
    }

    fn alpn(protocols: &[&[u8]]) -> (u16, Vec<u8>) {
        let mut list = Vec::new();
        for protocol in protocols {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        (EXT_ALPN, data)
    }

    /// Name, bytes, tunnel host, expected outcome.
    type Case = (
        &'static str,
        Vec<u8>,
        &'static str,
        Result<(), ClientHelloError>,
    );

    #[test]
    fn client_hello_gate() {
        let worker = worker_hello();
        let tail = &worker[5..];
        let mut split_over_records = vec![RECORD_HANDSHAKE, 0x03, 0x01, 0x00, 0x0a];
        split_over_records.extend_from_slice(&tail[..10]);
        split_over_records.extend_from_slice(&[RECORD_HANDSHAKE, 0x03, 0x01]);
        split_over_records.extend_from_slice(&((tail.len() - 10) as u16).to_be_bytes());
        split_over_records.extend_from_slice(&tail[10..]);

        let good = [sni("rpc.example"), alpn(&[ALPN_HTTP_1_1])];
        let cases: Vec<Case> = vec![
            ("worker fixture", worker.clone(), WORKER_HOST, Ok(())),
            (
                "worker fixture, upper-case host",
                worker.clone(),
                "RPC.Example",
                Ok(()),
            ),
            (
                "split over two records",
                split_over_records,
                WORKER_HOST,
                Ok(()),
            ),
            (
                "worker fixture, other host",
                worker.clone(),
                "other.example",
                Err(ClientHelloError::SniMismatch),
            ),
            (
                "truncated",
                worker[..worker.len() - 1].to_vec(),
                WORKER_HOST,
                Err(ClientHelloError::Incomplete {
                    needed: worker.len(),
                    have: worker.len() - 1,
                }),
            ),
            (
                "no server name",
                hello_with(&[alpn(&[ALPN_HTTP_1_1])]),
                WORKER_HOST,
                Err(ClientHelloError::MissingSni),
            ),
            (
                "no ALPN",
                hello_with(&[sni(WORKER_HOST)]),
                WORKER_HOST,
                Err(ClientHelloError::Alpn),
            ),
            (
                "h2 offered",
                hello_with(&[sni(WORKER_HOST), alpn(&[b"h2", ALPN_HTTP_1_1])]),
                WORKER_HOST,
                Err(ClientHelloError::Alpn),
            ),
            (
                "other ALPN",
                hello_with(&[sni(WORKER_HOST), alpn(&[b"smtp"])]),
                WORKER_HOST,
                Err(ClientHelloError::Alpn),
            ),
            (
                "early data",
                hello_with(&[
                    good[0].clone(),
                    good[1].clone(),
                    (EXT_EARLY_DATA, Vec::new()),
                ]),
                WORKER_HOST,
                Err(ClientHelloError::EarlyData),
            ),
            (
                "pre-shared key",
                hello_with(&[
                    good[0].clone(),
                    good[1].clone(),
                    (EXT_PRE_SHARED_KEY, vec![0; 4]),
                ]),
                WORKER_HOST,
                Err(ClientHelloError::PreSharedKey),
            ),
            (
                "empty session ticket extension",
                hello_with(&[
                    good[0].clone(),
                    good[1].clone(),
                    (EXT_SESSION_TICKET, Vec::new()),
                ]),
                WORKER_HOST,
                Ok(()),
            ),
            (
                "session ticket",
                hello_with(&[
                    good[0].clone(),
                    good[1].clone(),
                    (EXT_SESSION_TICKET, vec![0; 16]),
                ]),
                WORKER_HOST,
                Err(ClientHelloError::SessionTicket),
            ),
            (
                "plaintext HTTP",
                b"GET / HTTP/1.1\r\nHost: rpc.example\r\n\r\n".to_vec(),
                WORKER_HOST,
                Err(ClientHelloError::NotHandshake(b'G')),
            ),
            (
                "SMTP",
                b"EHLO rpc.example\r\n".to_vec(),
                WORKER_HOST,
                Err(ClientHelloError::NotHandshake(b'E')),
            ),
        ];
        for (name, data, host, expected) in cases {
            assert_eq!(check_client_hello(&data, host), expected, "{name}");
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        let worker = worker_hello();
        for cut in 0..worker.len() {
            assert!(check_client_hello(&worker[..cut], WORKER_HOST).is_err());
        }
        let mut corrupted = worker;
        for index in 5..corrupted.len() {
            let original = corrupted[index];
            corrupted[index] = 0xff;
            let _ = check_client_hello(&corrupted, WORKER_HOST);
            corrupted[index] = original;
        }
    }
}
