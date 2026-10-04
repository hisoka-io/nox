//! The KPS listener, connection admission, per-connection stream handling,
//! background tasks and graceful shutdown.
//!
//! Lifecycle of a connection:
//! 1. `kps::Listener::accept` yields an authenticated, established connection
//!    (WebRTC or QUIC; the API does not say which).
//! 2. The global and per-IP caps admit it or close it with `queue-full`.
//! 3. Each accepted stream is one HTTP/1.1 exchange ([`crate::exchange`]);
//!    beyond `max_streams_per_connection` concurrent streams, new streams are
//!    reset with `queue-full`.
//! 4. The connection is closed when the peer leaves, after
//!    `limits.conn_idle_timeout_secs` without streams, after
//!    `limits.conn_max_lifetime_secs`, or at shutdown once its in-flight
//!    exchanges finish (bounded by the grace period).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kps::ErrorCode;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::app::{metadata_document, App, RateLimiters};
use crate::bundles::{log_report, BundleSettings, BundleStore};
use crate::config::Settings;
use crate::error::{BundleError, StartError};
use crate::exchange::{serve_stream, StreamOutcome};
use crate::identity::{self, format_address};
use crate::limits::ConnLimiter;
use crate::metrics::{self, HealthInfo, Metrics};
use crate::proxy::{SharedResponse, UpstreamClient};

/// A started server. Dropping it does not stop it; call
/// [`RunningServer::shutdown`] and then [`RunningServer::wait`].
#[derive(Debug)]
pub struct RunningServer {
    certhash: String,
    port: u16,
    addresses: Vec<String>,
    admin_addr: SocketAddr,
    shutdown: CancellationToken,
    health: Arc<HealthInfo>,
    metrics: Arc<Metrics>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningServer {
    /// The certhash clients pin (stable for a given key file).
    #[must_use]
    pub fn certhash(&self) -> &str {
        &self.certhash
    }

    /// The UDP port the listener bound.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The published `ip:port:certhash` addresses.
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// The address to dial on this host (loopback), for tests and tooling.
    #[must_use]
    pub fn local_address(&self) -> String {
        format_address(IpAddr::from([127, 0, 0, 1]), self.port, &self.certhash)
    }

    /// Where `/metrics` and `/healthz` are served.
    #[must_use]
    pub fn admin_addr(&self) -> SocketAddr {
        self.admin_addr
    }

    #[must_use]
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Starts a graceful shutdown: no new connections or streams, in-flight
    /// exchanges get the grace period, then every connection is closed.
    pub fn shutdown(&self) {
        self.health.shutting_down.store(true, Ordering::Relaxed);
        self.shutdown.cancel();
    }

    /// A token that triggers [`RunningServer::shutdown`] when cancelled.
    #[must_use]
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Waits for every server task to finish (after a shutdown).
    pub async fn wait(self) {
        for task in self.tasks {
            if let Err(e) = task.await {
                warn!(error = %e, "server task ended abnormally");
            }
        }
    }
}

/// Loads the identity and bundles, binds the KPS listener and the admin
/// endpoint, and starts serving.
pub async fn start(settings: Settings) -> Result<RunningServer, StartError> {
    let settings = Arc::new(settings);
    let metrics = Metrics::new();
    match crate::preflight::scan_host() {
        Ok(findings) => {
            for finding in &findings {
                warn!("{}", crate::preflight::describe(finding));
            }
        }
        Err(e) => warn!(error = %e, "cannot list network interfaces for the loopback check"),
    }

    let identity =
        identity::load_expected(&settings.key_file, settings.expected_certhash.as_deref())?;
    let certhash = identity.certhash.clone();

    let bundles = match &settings.keccak_dir {
        None => None,
        Some(dir) => {
            if !dir.is_dir() {
                return Err(StartError::Bundles(BundleError::ReadDir {
                    path: dir.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "keccak_dir is not a directory; create it (the nox-kps-bundles volume) or set keccak_dir = \"\" to turn the bundle resolver off",
                    ),
                }));
            }
            let bundle_settings = BundleSettings {
                dir: dir.clone(),
                max_bundle_bytes: settings.limits.max_bundle_bytes,
                max_bundles: settings.limits.max_bundles,
                gzip: settings.limits.bundle_gzip,
            };
            let (store, report) = BundleStore::load(bundle_settings)?;
            log_report(&report, dir);
            info!(dir = %dir.display(), loaded = store.len(), "worker bundle resolver enabled");
            metrics.bundles_loaded.set(store.len() as i64);
            Some(Arc::new(store))
        }
    };

    let listener = kps::listen(
        &settings.listen.to_string(),
        kps::ListenOptions {
            identity: Some(identity),
            key_file: None,
        },
    )
    .await
    .map_err(|source| StartError::Listen {
        addr: settings.listen,
        source,
    })?;
    let port = listener.port();
    let addresses: Vec<String> = settings
        .advertise
        .iter()
        .map(|ip| format_address(*ip, port, &certhash))
        .collect();

    let admin_listener = tokio::net::TcpListener::bind(settings.admin_listen)
        .await
        .map_err(|source| StartError::AdminBind {
            addr: settings.admin_listen,
            source,
        })?;
    let admin_addr = admin_listener
        .local_addr()
        .map_err(|source| StartError::AdminBind {
            addr: settings.admin_listen,
            source,
        })?;

    let metadata_json = metadata_document(&settings, &addresses, bundles.is_some())
        .map_err(StartError::Metadata)?;
    let l = &settings.limits;
    let app = Arc::new(App {
        upstream: UpstreamClient::new(
            l.upstream_connect_timeout,
            l.upstream_pool_idle_timeout,
            l.upstream_pool_max_idle,
            settings.client_ip_header.clone(),
        ),
        metadata_json,
        bundles: bundles.clone(),
        metrics: Arc::clone(&metrics),
        inflight: Arc::new(Semaphore::new(l.max_inflight_upstream)),
        bundle_streams: Arc::new(Semaphore::new(l.max_concurrent_bundle_streams)),
        conn_limiter: ConnLimiter::new(
            l.max_connections,
            l.max_connections_per_ip,
            l.ipv6_prefix_len,
        ),
        rate: RateLimiters::new(&settings),
        topology: SharedResponse::new(l.topology_cache),
        health: SharedResponse::new(l.health_cache),
        settings: Arc::clone(&settings),
    });

    let shutdown = CancellationToken::new();
    let health = Arc::new(HealthInfo {
        certhash: certhash.clone(),
        addresses: addresses.clone(),
        shutting_down: AtomicBool::new(false),
        listener_alive: AtomicBool::new(true),
    });

    let mut tasks = vec![
        tokio::spawn(accept_loop(
            listener,
            Arc::clone(&app),
            Arc::clone(&health),
            shutdown.clone(),
        )),
        tokio::spawn(metrics::serve(
            admin_listener,
            Arc::clone(&metrics),
            Arc::clone(&health),
            metrics::AdminTimeouts {
                header_read: l.admin_header_read_timeout,
                conn_lifetime: l.admin_conn_max_lifetime,
                accept_retry: l.admin_accept_retry,
            },
            shutdown.clone(),
        )),
        tokio::spawn(housekeeping(Arc::clone(&app), shutdown.clone())),
    ];
    if let (Some(store), Some(interval)) = (bundles, l.bundle_rescan) {
        tasks.push(tokio::spawn(rescan_loop(
            store,
            interval,
            Arc::clone(&metrics),
            shutdown.clone(),
        )));
    }

    Ok(RunningServer {
        certhash,
        port,
        addresses,
        admin_addr,
        shutdown,
        health,
        metrics,
        tasks,
    })
}

async fn accept_loop(
    listener: kps::Listener,
    app: Arc<App>,
    health: Arc<HealthInfo>,
    shutdown: CancellationToken,
) {
    let tracker = TaskTracker::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => {
                    tracker.spawn(handle_conn(conn, Arc::clone(&app), shutdown.clone(), tracker.clone()));
                }
                Err(e) => {
                    warn!(error = %e, "KPS listener stopped accepting connections");
                    health.listener_alive.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
    tracker.close();
    let grace = app.settings.shutdown_grace;
    if tokio::time::timeout(grace, tracker.wait()).await.is_err() {
        warn!(
            tasks = tracker.len(),
            grace_ms = grace.as_millis() as u64,
            "shutdown grace period elapsed with exchanges in flight; closing them"
        );
    }
    listener.close().await;
    info!("KPS listener closed");
}

/// Per-connection state shared with its stream tasks.
#[derive(Debug)]
struct Activity {
    /// Last time a stream was accepted or finished.
    last: Mutex<Instant>,
    /// Streams in a row that hit `limits.stream_timeout_ms`.
    consecutive_timeouts: AtomicUsize,
    /// Cancelled when `limits.max_stream_timeouts_per_connection` is reached:
    /// the transport is treated as stalled and the connection is closed, so
    /// its buffers are released and the client redials.
    stalled: CancellationToken,
}

impl Activity {
    fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            consecutive_timeouts: AtomicUsize::new(0),
            stalled: CancellationToken::new(),
        }
    }

    fn touch(&self) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn last(&self) -> Instant {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records how a stream ended.
    fn record(&self, outcome: StreamOutcome, max_timeouts: usize) {
        match outcome {
            StreamOutcome::StreamTimeout => {
                let n = self.consecutive_timeouts.fetch_add(1, Ordering::Relaxed) + 1;
                if n >= max_timeouts {
                    self.stalled.cancel();
                }
            }
            StreamOutcome::Completed => self.consecutive_timeouts.store(0, Ordering::Relaxed),
            StreamOutcome::HeaderTimeout
            | StreamOutcome::ProtocolError
            | StreamOutcome::Abandoned
            | StreamOutcome::Io => {}
        }
    }
}

/// Why a connection was closed (metric label).
#[derive(Debug, Clone, Copy)]
enum CloseReason {
    Peer,
    Idle,
    Lifetime,
    Stalled,
    Shutdown,
}

impl CloseReason {
    fn label(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Idle => "idle",
            Self::Lifetime => "lifetime",
            Self::Stalled => "stalled",
            Self::Shutdown => "shutdown",
        }
    }
}

async fn handle_conn(
    conn: Box<dyn kps::Conn>,
    app: Arc<App>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    let client_ip = conn.remote_addr().ip().to_canonical();
    let permit = match app.conn_limiter.try_admit(client_ip) {
        Ok(permit) => permit,
        Err(reason) => {
            Metrics::reason(&app.metrics.connections_rejected, reason.label());
            debug!(reason = reason.label(), "KPS connection refused");
            let _ = tokio::time::timeout(
                app.settings.limits.close_timeout,
                conn.close_with_error(ErrorCode::QueueFull),
            )
            .await;
            return;
        }
    };
    app.metrics.connections_accepted.inc();
    app.metrics.connections_active.inc();

    let limits = &app.settings.limits;
    let max_streams = limits.max_streams_per_connection;
    let slots = Arc::new(Semaphore::new(max_streams));
    let activity = Arc::new(Activity::new());
    let idle_timeout = limits.conn_idle_timeout;
    let end_of_life = tokio::time::Instant::now() + limits.conn_max_lifetime;

    let reason = loop {
        let busy = slots.available_permits() < max_streams;
        let idle_at = if busy {
            Instant::now() + idle_timeout
        } else {
            activity.last() + idle_timeout
        };
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break CloseReason::Shutdown,
            () = tokio::time::sleep_until(end_of_life) => break CloseReason::Lifetime,
            () = activity.stalled.cancelled() => break CloseReason::Stalled,
            accepted = conn.accept_stream() => match accepted {
                Ok(stream) => {
                    activity.touch();
                    if let Ok(slot) = Arc::clone(&slots).try_acquire_owned() {
                        tracker.spawn(run_stream(stream, Arc::clone(&app), client_ip, slot, Arc::clone(&activity)));
                    } else {
                        Metrics::reason(&app.metrics.streams_rejected, "per_connection_limit");
                        let close_timeout = limits.close_timeout;
                        tracker.spawn(async move {
                            let mut stream = stream;
                            let _ = tokio::time::timeout(
                                close_timeout,
                                stream.close_with_error(ErrorCode::QueueFull),
                            )
                            .await;
                        });
                    }
                }
                Err(_) => break CloseReason::Peer,
            },
            () = tokio::time::sleep_until(idle_at.into()) => {
                let idle = slots.available_permits() == max_streams
                    && activity.last().elapsed() >= idle_timeout;
                if idle {
                    break CloseReason::Idle;
                }
            }
        }
    };

    // Let in-flight exchanges on this connection finish before closing it.
    // At shutdown the accept loop bounds the whole drain by the grace period.
    let drain = Arc::clone(&slots).acquire_many_owned(max_streams as u32);
    let drain_limit = match reason {
        CloseReason::Shutdown => app.settings.shutdown_grace,
        CloseReason::Peer | CloseReason::Idle | CloseReason::Lifetime => limits.stream_timeout,
        // The transport is not moving data; waiting longer only holds buffers.
        CloseReason::Stalled => Duration::ZERO,
    };
    let _ = tokio::time::timeout(drain_limit, drain).await;
    if matches!(reason, CloseReason::Shutdown) {
        // A KPS close is immediate (QUIC CONNECTION_CLOSE, WebRTC teardown) and
        // drops data the client has not acknowledged yet. Give the final
        // responses time to land, or until the client closes first.
        let _ = tokio::time::timeout(app.settings.shutdown_linger, conn.closed()).await;
    }

    // Bounded: closing a stalled transport must not hold this task.
    let close_timeout = limits.close_timeout;
    let _ = match reason {
        CloseReason::Idle | CloseReason::Lifetime | CloseReason::Stalled => {
            tokio::time::timeout(close_timeout, conn.close_with_error(ErrorCode::Timeout)).await
        }
        CloseReason::Peer | CloseReason::Shutdown => {
            tokio::time::timeout(close_timeout, conn.close()).await
        }
    };
    Metrics::reason(&app.metrics.connections_closed, reason.label());
    app.metrics.connections_active.dec();
    drop(permit);
}

async fn run_stream(
    stream: Box<dyn kps::Stream>,
    app: Arc<App>,
    client_ip: IpAddr,
    slot: OwnedSemaphorePermit,
    activity: Arc<Activity>,
) {
    app.metrics.streams_active.inc();
    let outcome = serve_stream(stream, Arc::clone(&app), client_ip).await;
    if outcome != StreamOutcome::Completed {
        Metrics::reason(&app.metrics.stream_failures, outcome.label());
    }
    app.metrics.streams_active.dec();
    activity.record(
        outcome,
        app.settings.limits.max_stream_timeouts_per_connection,
    );
    activity.touch();
    drop(slot);
}

/// Periodic work: sweep idle rate-limit buckets every
/// `limits.rate_limit_sweep_secs`, and log a counter summary every
/// `summary_interval_secs` (counts only: no addresses, no identifiers).
async fn housekeeping(app: Arc<App>, shutdown: CancellationToken) {
    let ticker = |interval: Duration| {
        let mut t = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t
    };
    let mut sweep = ticker(app.settings.limits.rate_limit_sweep);
    let mut summary = app.settings.summary_interval.map(ticker);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            _ = sweep.tick() => app.rate.sweep(),
            () = next_tick(summary.as_mut()) => {
                crate::telemetry::log_summary(&app.metrics, app.conn_limiter.active());
            }
        }
    }
}

/// The next tick of an optional interval; never ready without one.
async fn next_tick(interval: Option<&mut tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

async fn rescan_loop(
    store: Arc<BundleStore>,
    interval: Duration,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            _ = ticker.tick() => {
                let scan_store = Arc::clone(&store);
                match tokio::task::spawn_blocking(move || scan_store.rescan()).await {
                    Ok(Ok(report)) => {
                        log_report(&report, &store.settings().dir);
                        metrics.bundles_loaded.set(store.len() as i64);
                    }
                    Ok(Err(e)) => warn!(error = %e, "worker bundle rescan failed; serving the previous index"),
                    Err(e) => warn!(error = %e, "worker bundle rescan task failed; serving the previous index"),
                }
            }
        }
    }
}
