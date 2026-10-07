//! End-to-end TLS tunnels through the exit's `TunnelHandler`: a rustls client talks to a
//! local HTTPS server and the exit relays only TLS records, answering on real SURBs.

use nox_core::models::payloads::decode_payload;
use nox_core::IEventSubscriber;
use nox_core::{
    NoxEvent, RelayerPayload, TunnelFinV1, TunnelOpenV1, TunnelRejectCodeV1, TunnelReplyV1,
    TunnelRequestV1, TUNNEL_ID_LEN,
};
use nox_crypto::{PathHop, Surb, SurbRecovery, HEADER_SIZE};
use nox_node::config::{HttpConfig, TunnelConfig};
use nox_node::services::handlers::tunnel::TunnelHandler;
use nox_node::services::response_packer::ResponsePacker;
use nox_node::telemetry::metrics::MetricsService;
use nox_node::TokioEventBus;
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_rustls::rustls;
use tokio_util::sync::CancellationToken;

const HOST: &str = "localhost";
const CANARY: &str = "0xcanary5f1e2d3c4b5a69788796a5b4c3d2e1f0";
const HOLD_MS: u32 = 20_000;
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// HTTPS server on 127.0.0.1 answering every request with `body_len` bytes. It records the
/// plaintext it reads so tests can count upstream writes.
struct Upstream {
    port: u16,
    ca: rustls::pki_types::CertificateDer<'static>,
    received: Arc<Mutex<Vec<u8>>>,
}

async fn start_upstream(body_len: usize) -> Upstream {
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec![HOST.to_string()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf certificate");
    let mut server_config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .expect("server certificate");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while !request_complete(&request) {
                    match tls.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                log.lock().extend_from_slice(&request);
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                )
                .into_bytes();
                response.extend((0..body_len).map(|i| (i % 251) as u8));
                if tls.write_all(&response).await.is_ok() {
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    Upstream {
        port,
        ca: ca.der().clone(),
        received,
    }
}

fn request_complete(request: &[u8]) -> bool {
    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    request.len() >= end + 4 + length
}

fn http_request() -> Vec<u8> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["{CANARY}","latest"]}}"#
    );
    format!(
        "POST /v1/secret-api-key HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn tunnel_config(port: u16) -> TunnelConfig {
    TunnelConfig {
        enabled: true,
        allowed_ports: vec![port],
        ..TunnelConfig::default()
    }
}

struct Exit {
    handler: TunnelHandler,
    events: broadcast::Receiver<NoxEvent>,
}

fn start_exit(config: TunnelConfig, allow_private_ips: bool) -> Exit {
    let bus = TokioEventBus::new(4_096);
    let events = bus.subscribe();
    let http = HttpConfig {
        allow_private_ips,
        ..HttpConfig::default()
    };
    let handler = TunnelHandler::new(
        config,
        &http,
        Arc::new(ResponsePacker::new()),
        Arc::new(bus),
        MetricsService::new(),
        CancellationToken::new(),
    );
    Exit { handler, events }
}

/// The client side of one tunnel: SURBs, reply decryption, reordering by offset and a
/// rustls connection fed from the contiguous bytes.
struct Client {
    id: [u8; TUNNEL_ID_LEN],
    seq: u32,
    tls: rustls::ClientConnection,
    path: Vec<PathHop>,
    recoveries: HashMap<[u8; 16], SurbRecovery>,
    parts: BTreeMap<u64, Vec<u8>>,
    contiguous: u64,
    plaintext: Vec<u8>,
    /// Every byte the client handed to the exit, to check for plaintext.
    sent: Vec<u8>,
}

impl Client {
    fn new(ca: &rustls::pki_types::CertificateDer<'static>, sni: &str) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).expect("root");
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let name = rustls::pki_types::ServerName::try_from(sni.to_string()).expect("name");
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        Self {
            id: rand::random(),
            seq: 0,
            tls: rustls::ClientConnection::new(Arc::new(config), name).expect("client"),
            path: vec![PathHop {
                public_key: x25519_dalek::PublicKey::from(&secret),
                address: "/ip4/127.0.0.1/tcp/9000".to_string(),
            }],
            recoveries: HashMap::new(),
            parts: BTreeMap::new(),
            contiguous: 0,
            plaintext: Vec::new(),
            sent: Vec::new(),
        }
    }

    fn surbs(&mut self, count: usize) -> Vec<Surb> {
        (0..count)
            .map(|_| {
                let (surb, mut recovery) = Surb::new(&self.path, rand::random(), 0).expect("SURB");
                recovery.layer_keys.clear();
                self.recoveries.insert(surb.id, recovery);
                surb
            })
            .collect()
    }

    fn tls_out(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut out).expect("write_tls");
        }
        self.sent.extend_from_slice(&out);
        out
    }

    fn request(
        &mut self,
        open_port: Option<u16>,
        data: Vec<u8>,
        surbs: usize,
    ) -> (TunnelRequestV1, Vec<Surb>) {
        let request = TunnelRequestV1 {
            tunnel_id: self.id,
            seq: self.seq,
            open: open_port.map(|port| TunnelOpenV1 {
                host: HOST.to_string(),
                port,
            }),
            ack_offset: self.contiguous,
            data,
            close: false,
            hold_ms: HOLD_MS,
        };
        (request, self.surbs(surbs))
    }

    /// Next reply the exit sent on one of this client's SURBs.
    async fn reply(&mut self, exit: &mut Exit) -> TunnelReplyV1 {
        loop {
            let event = tokio::time::timeout(REPLY_TIMEOUT, exit.events.recv())
                .await
                .expect("reply in time")
                .expect("event bus open");
            let NoxEvent::SendPacket {
                data, reply_handle, ..
            } = event
            else {
                continue;
            };
            let Some(recovery) = reply_handle.and_then(|id| self.recoveries.remove(&id)) else {
                continue;
            };
            let opened = recovery.decrypt(&data[HEADER_SIZE..]).expect("decrypt");
            let RelayerPayload::ServiceResponse { fragment, .. } =
                decode_payload(&opened).expect("service response")
            else {
                panic!("expected a service response");
            };
            return decode_payload(&fragment.data).expect("tunnel reply");
        }
    }

    /// Stores a data part, feeds contiguous bytes to TLS, and returns its `fin`.
    fn absorb(&mut self, reply: &TunnelReplyV1) -> Option<TunnelFinV1> {
        let TunnelReplyV1::Data {
            offset, data, fin, ..
        } = reply
        else {
            panic!("unexpected rejection {reply:?}");
        };
        self.parts.insert(*offset, data.clone());
        // Parts resent after a copy may start below the contiguous point.
        while let Some(tail) = self.parts.iter().find_map(|(offset, data)| {
            let skip = usize::try_from(self.contiguous.checked_sub(*offset)?).ok()?;
            data.get(skip..)
                .filter(|tail| !tail.is_empty())
                .map(<[u8]>::to_vec)
        }) {
            let mut input = tail.as_slice();
            let mut buffer = [0_u8; 16 * 1024];
            while !input.is_empty() {
                self.tls.read_tls(&mut input).expect("read_tls");
                self.tls.process_new_packets().expect("TLS records verify");
                while let Ok(n @ 1..) = self.tls.reader().read(&mut buffer) {
                    self.plaintext.extend_from_slice(&buffer[..n]);
                }
            }
            self.contiguous += tail.len() as u64;
        }
        let contiguous = self.contiguous;
        self.parts
            .retain(|offset, data| *offset + data.len() as u64 > contiguous);
        *fin
    }

    /// Opens the tunnel and completes the TLS handshake.
    async fn handshake(&mut self, exit: &mut Exit, port: u16) {
        let hello = self.tls_out();
        let (request, surbs) = self.request(Some(port), hello, 2);
        exit.handler.handle(request, surbs);
        while self.tls.is_handshaking() {
            let reply = self.reply(exit).await;
            self.absorb(&reply);
        }
    }

    /// Sends the client Finished and the HTTP request as the next seq.
    fn send_request(&mut self, exit: &Exit, surbs: usize) -> TunnelRequestV1 {
        self.tls
            .writer()
            .write_all(&http_request())
            .expect("write request");
        self.seq += 1;
        let data = self.tls_out();
        let (request, surbs) = self.request(None, data, surbs);
        exit.handler.handle(request.clone(), surbs);
        request
    }

    fn copy(&mut self, exit: &Exit, mut request: TunnelRequestV1, surbs: usize) {
        request.ack_offset = self.contiguous;
        let surbs = self.surbs(surbs);
        exit.handler.handle(request, surbs);
    }

    fn response_body(&self) -> Option<&[u8]> {
        let end = self.plaintext.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&self.plaintext[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))?
            .trim()
            .parse()
            .ok()?;
        self.plaintext.get(end + 4..end + 4 + length)
    }
}

fn expected_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn rejection(reply: &TunnelReplyV1) -> TunnelRejectCodeV1 {
    match reply {
        TunnelReplyV1::Rejected { code, .. } => *code,
        TunnelReplyV1::Data { .. } => panic!("expected a rejection, got {reply:?}"),
    }
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn round_trip_writes_once_and_hides_the_request() {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    // Global, so callsites first hit on other test threads still reach this writer.
    tracing::subscriber::set_global_default(subscriber).expect("only this test sets a subscriber");

    let body_len = 4_000;
    let upstream = start_upstream(body_len).await;
    let mut exit = start_exit(tunnel_config(upstream.port), true);
    let mut client = Client::new(&upstream.ca, HOST);
    client.handshake(&mut exit, upstream.port).await;

    let request = client.send_request(&exit, 4);
    client.copy(&exit, request, 4);
    while client.response_body().is_none() {
        let reply = client.reply(&mut exit).await;
        client.absorb(&reply);
    }
    assert_eq!(
        client.response_body(),
        Some(expected_body(body_len).as_slice())
    );
    assert_eq!(
        *upstream.received.lock(),
        http_request(),
        "one upstream write"
    );

    let canary = CANARY.as_bytes();
    assert!(!client.sent.windows(canary.len()).any(|w| w == canary));
    let logged = logs.0.lock();
    assert!(!logged.is_empty(), "debug logs were captured");
    assert!(!logged.windows(canary.len()).any(|w| w == canary));
    assert!(!logged.windows(14).any(|w| w == b"secret-api-key"));
}

#[tokio::test]
async fn policy_rejects_before_connecting() {
    let upstream = start_upstream(10).await;
    let cases: [(&str, u16, &str, bool, TunnelRejectCodeV1); 4] = [
        (
            "port",
            upstream.port + 1,
            HOST,
            true,
            TunnelRejectCodeV1::PortNotAllowed,
        ),
        (
            "IP literal",
            upstream.port,
            "127.0.0.1",
            true,
            TunnelRejectCodeV1::HostNotAllowed,
        ),
        (
            "SNI mismatch",
            upstream.port,
            "other.localhost",
            true,
            TunnelRejectCodeV1::HostNotAllowed,
        ),
        (
            "private address",
            upstream.port,
            HOST,
            false,
            TunnelRejectCodeV1::DestinationBlocked,
        ),
    ];
    for (name, port, host, allow_private_ips, expected) in cases {
        let mut exit = start_exit(tunnel_config(upstream.port), allow_private_ips);
        let mut client = Client::new(&upstream.ca, HOST);
        let hello = client.tls_out();
        let (mut request, surbs) = client.request(Some(port), hello, 1);
        request.open = Some(TunnelOpenV1 {
            host: host.to_string(),
            port,
        });
        exit.handler.handle(request, surbs);
        assert_eq!(
            rejection(&client.reply(&mut exit).await),
            expected,
            "{name}"
        );
        assert_eq!(exit.handler.sessions(), 0, "{name}");
    }
    assert!(upstream.received.lock().is_empty());
}

#[tokio::test]
async fn flow_control_bounds_the_window_and_resumes_with_copies() {
    let body_len = 2 * 1024 * 1024;
    let upstream = start_upstream(body_len).await;
    let config = tunnel_config(upstream.port);
    let max_window = config.max_window_bytes;
    let mut exit = start_exit(config, true);
    let mut client = Client::new(&upstream.ca, HOST);
    client.handshake(&mut exit, upstream.port).await;

    let request = client.send_request(&exit, 4);
    let mut need_surbs = 0;
    while client.response_body().is_none() {
        let reply = client.reply(&mut exit).await;
        assert!(exit.handler.buffered_bytes() <= max_window);
        match client.absorb(&reply) {
            Some(TunnelFinV1::NeedSurbs) => {
                need_surbs += 1;
                client.copy(&exit, request.clone(), 32);
            }
            Some(TunnelFinV1::Expired) => panic!("exchange expired"),
            _ => {}
        }
    }
    assert!(
        need_surbs >= 2,
        "the first exchange and each full window ask for SURBs"
    );
    assert_eq!(
        client.response_body(),
        Some(expected_body(body_len).as_slice())
    );
}

#[tokio::test]
async fn limits_evict_idle_tunnels_and_release_slots() {
    let upstream = start_upstream(256 * 1024).await;
    let config = TunnelConfig {
        max_sessions: 1,
        min_hold_ms: 50,
        session_idle_secs: 1,
        max_session_bytes: 64 * 1024,
        ..tunnel_config(upstream.port)
    };

    // An idle tunnel is evicted for a new open; while that one is busy, opens are refused.
    let mut exit = start_exit(config.clone(), true);
    let mut idle = Client::new(&upstream.ca, HOST);
    let hello = idle.tls_out();
    let (mut request, surbs) = idle.request(Some(upstream.port), hello, 2);
    request.hold_ms = 50;
    exit.handler.handle(request, surbs);
    loop {
        let reply = idle.reply(&mut exit).await;
        if idle.absorb(&reply) == Some(TunnelFinV1::Expired) {
            break;
        }
    }
    let mut busy = Client::new(&upstream.ca, HOST);
    busy.handshake(&mut exit, upstream.port).await;
    let mut refused = Client::new(&upstream.ca, HOST);
    let hello = refused.tls_out();
    let (request, surbs) = refused.request(Some(upstream.port), hello, 1);
    exit.handler.handle(request, surbs);
    assert_eq!(
        rejection(&refused.reply(&mut exit).await),
        TunnelRejectCodeV1::SessionLimit
    );
    idle.seq += 1;
    let (request, surbs) = idle.request(None, Vec::new(), 1);
    exit.handler.handle(request, surbs);
    assert_eq!(
        rejection(&idle.reply(&mut exit).await),
        TunnelRejectCodeV1::Expired
    );

    // The byte limit closes the busy tunnel.
    busy.send_request(&exit, 8);
    let code = loop {
        match busy.reply(&mut exit).await {
            TunnelReplyV1::Rejected { code, .. } => break code,
            reply => {
                busy.absorb(&reply);
            }
        }
    };
    assert_eq!(code, TunnelRejectCodeV1::ByteLimit);

    // A failed connect releases its slot.
    let closed_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        listener.local_addr().expect("address").port()
    };
    let mut exit = start_exit(
        TunnelConfig {
            allowed_ports: vec![upstream.port, closed_port],
            ..config
        },
        true,
    );
    let mut failed = Client::new(&upstream.ca, HOST);
    let hello = failed.tls_out();
    let (request, surbs) = failed.request(Some(closed_port), hello, 1);
    exit.handler.handle(request, surbs);
    assert_eq!(
        rejection(&failed.reply(&mut exit).await),
        TunnelRejectCodeV1::ConnectFailed
    );
    let mut next = Client::new(&upstream.ca, HOST);
    next.handshake(&mut exit, upstream.port).await;

    // An idle tunnel expires.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let request = next.send_request(&exit, 1);
    assert_eq!(request.seq, 1);
    assert_eq!(
        rejection(&next.reply(&mut exit).await),
        TunnelRejectCodeV1::Expired
    );
}
