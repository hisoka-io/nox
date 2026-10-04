//! Connection admission (a global cap and a per-client-IP cap) and per-IP
//! request rate limits (token buckets per route class). Clients are keyed the
//! way the node's ingress rate limiter keys them (IPv4 address, IPv6 prefix),
//! so one host cannot hold every slot, and these limits replace the nginx
//! limits that the KPS path does not pass through.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use crate::config::Rate;

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    /// `limits.max_connections` connections are already open.
    GlobalLimit,
    /// The client's IP (or IPv6 prefix) already holds
    /// `limits.max_connections_per_ip` connections.
    PerIpLimit,
}

impl AdmitError {
    /// Metric label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::GlobalLimit => "global_limit",
            Self::PerIpLimit => "per_ip_limit",
        }
    }
}

#[derive(Debug, Default)]
struct State {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Counts open connections globally and per client bucket.
#[derive(Debug)]
pub struct ConnLimiter {
    state: Mutex<State>,
    max_total: usize,
    max_per_ip: usize,
    ipv6_prefix_len: u8,
}

impl ConnLimiter {
    #[must_use]
    pub fn new(max_total: usize, max_per_ip: usize, ipv6_prefix_len: u8) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            max_total,
            max_per_ip,
            ipv6_prefix_len,
        })
    }

    /// Admits a connection from `ip`, or says which cap it hit. The returned
    /// permit releases the slot when dropped.
    pub fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnPermit, AdmitError> {
        let bucket = client_bucket(ip, self.ipv6_prefix_len);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.total >= self.max_total {
            return Err(AdmitError::GlobalLimit);
        }
        let held = state.per_ip.get(&bucket).copied().unwrap_or(0);
        if held >= self.max_per_ip {
            return Err(AdmitError::PerIpLimit);
        }
        state.total += 1;
        state.per_ip.insert(bucket, held + 1);
        Ok(ConnPermit {
            limiter: Arc::clone(self),
            bucket,
        })
    }

    /// Connections currently admitted.
    #[must_use]
    pub fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }

    /// Distinct client buckets currently holding connections.
    #[must_use]
    pub fn active_buckets(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .per_ip
            .len()
    }

    fn release(&self, bucket: IpAddr) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.per_ip.get_mut(&bucket) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.per_ip.remove(&bucket);
            }
        }
    }
}

/// One admitted connection; releases its slot on drop.
#[derive(Debug)]
pub struct ConnPermit {
    limiter: Arc<ConnLimiter>,
    bucket: IpAddr,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.limiter.release(self.bucket);
    }
}

/// Why a request was refused by a [`RateLimiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimited {
    /// The client's bucket is empty.
    Exhausted,
    /// `limits.rate_limit_max_clients` buckets are all active.
    TableFull,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-client token buckets for one route class.
#[derive(Debug)]
pub struct RateLimiter {
    rate: Rate,
    ipv6_prefix_len: u8,
    max_clients: usize,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(rate: Rate, ipv6_prefix_len: u8, max_clients: usize) -> Self {
        Self {
            rate,
            ipv6_prefix_len,
            max_clients,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token for `ip`, refilling at `rate.per_second` up to
    /// `rate.burst`.
    pub fn check(&self, ip: IpAddr) -> Result<(), RateLimited> {
        self.check_at(ip, Instant::now())
    }

    /// [`RateLimiter::check`] at a given time (tests).
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), RateLimited> {
        let key = client_bucket(ip, self.ipv6_prefix_len);
        let burst = f64::from(self.rate.burst);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !buckets.contains_key(&key) && buckets.len() >= self.max_clients {
            Self::sweep_locked(&mut buckets, self.rate, now);
            if buckets.len() >= self.max_clients {
                return Err(RateLimited::TableFull);
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * f64::from(self.rate.per_second)).min(burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(RateLimited::Exhausted)
        }
    }

    /// Drops buckets that have refilled completely (idle clients).
    pub fn sweep(&self) {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        Self::sweep_locked(&mut buckets, self.rate, Instant::now());
    }

    /// Client buckets currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn sweep_locked(buckets: &mut HashMap<IpAddr, Bucket>, rate: Rate, now: Instant) {
        let burst = f64::from(rate.burst);
        buckets.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens + elapsed * f64::from(rate.per_second) < burst
        });
        buckets.shrink_to_fit();
    }
}

/// The key a client is counted under: the IPv4 address (v4-mapped IPv6 is
/// treated as IPv4), or the IPv6 address masked to `ipv6_prefix_len` bits.
#[must_use]
pub fn client_bucket(ip: IpAddr, ipv6_prefix_len: u8) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let bits = u32::from(ipv6_prefix_len.min(128));
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn per_ip_cap_applies_per_client_and_releases_on_drop() {
        let limiter = ConnLimiter::new(10, 2, 64);
        let a1 = limiter.try_admit(ip("203.0.113.7")).unwrap();
        let _a2 = limiter.try_admit(ip("203.0.113.7")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("203.0.113.7")).unwrap_err(),
            AdmitError::PerIpLimit
        );
        let _b = limiter.try_admit(ip("203.0.113.8")).unwrap();
        assert_eq!(limiter.active(), 3);
        drop(a1);
        assert_eq!(limiter.active(), 2);
        let _a3 = limiter.try_admit(ip("203.0.113.7")).unwrap();
    }

    #[test]
    fn global_cap_applies_across_clients() {
        let limiter = ConnLimiter::new(2, 2, 64);
        let _a = limiter.try_admit(ip("198.51.100.1")).unwrap();
        let _b = limiter.try_admit(ip("198.51.100.2")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("198.51.100.3")).unwrap_err(),
            AdmitError::GlobalLimit
        );
    }

    #[test]
    fn buckets_are_released_when_empty() {
        let limiter = ConnLimiter::new(4, 4, 64);
        let p = limiter.try_admit(ip("2001:db8::1")).unwrap();
        assert_eq!(limiter.active_buckets(), 1);
        drop(p);
        assert_eq!(limiter.active_buckets(), 0);
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn ipv6_clients_share_a_prefix_bucket() {
        let limiter = ConnLimiter::new(10, 1, 64);
        let _a = limiter.try_admit(ip("2001:db8:1:2:aaaa::1")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("2001:db8:1:2:bbbb::2")).unwrap_err(),
            AdmitError::PerIpLimit,
            "same /64"
        );
        let _c = limiter.try_admit(ip("2001:db8:1:3::1")).unwrap();
    }

    #[test]
    fn mapped_ipv4_counts_as_ipv4() {
        assert_eq!(
            client_bucket(ip("::ffff:203.0.113.7"), 64),
            ip("203.0.113.7")
        );
        let limiter = ConnLimiter::new(10, 1, 64);
        let _a = limiter.try_admit(ip("203.0.113.7")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("::ffff:203.0.113.7")).unwrap_err(),
            AdmitError::PerIpLimit
        );
    }

    #[test]
    fn token_bucket_admits_the_burst_then_the_rate() {
        let limiter = RateLimiter::new(Rate::new(20, 100), 64, 1000);
        let t0 = Instant::now();
        let a = ip("203.0.113.7");
        let admitted = (0..150).filter(|_| limiter.check_at(a, t0).is_ok()).count();
        assert_eq!(admitted, 100, "a burst of 150 at t=0 admits the burst size");
        assert_eq!(limiter.check_at(a, t0), Err(RateLimited::Exhausted));
        // 20 per second: after 0.5 s, 10 more.
        let t1 = t0 + std::time::Duration::from_millis(500);
        let admitted = (0..50).filter(|_| limiter.check_at(a, t1).is_ok()).count();
        assert_eq!(admitted, 10);
        // Another client has its own bucket.
        assert!(limiter.check_at(ip("203.0.113.8"), t1).is_ok());
    }

    #[test]
    fn token_buckets_share_an_ipv6_prefix() {
        let limiter = RateLimiter::new(Rate::new(1, 1), 64, 1000);
        let t0 = Instant::now();
        assert!(limiter.check_at(ip("2001:db8:1:2::1"), t0).is_ok());
        assert_eq!(
            limiter.check_at(ip("2001:db8:1:2::ffff"), t0),
            Err(RateLimited::Exhausted)
        );
    }

    #[test]
    fn the_client_table_is_bounded_and_swept() {
        let limiter = RateLimiter::new(Rate::new(10, 2), 64, 2);
        let t0 = Instant::now();
        assert!(limiter.check_at(ip("198.51.100.1"), t0).is_ok());
        assert!(limiter.check_at(ip("198.51.100.2"), t0).is_ok());
        assert_eq!(
            limiter.check_at(ip("198.51.100.3"), t0),
            Err(RateLimited::TableFull),
            "every tracked client is active"
        );
        // After the buckets refill, the idle entries are swept for a newcomer.
        let later = t0 + std::time::Duration::from_secs(1);
        assert!(limiter.check_at(ip("198.51.100.3"), later).is_ok());
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn prefix_lengths_mask_the_right_bits() {
        assert_eq!(client_bucket(ip("2001:db8::1"), 128), ip("2001:db8::1"));
        assert_eq!(client_bucket(ip("2001:db8:ffff::1"), 32), ip("2001:db8::"));
        assert_eq!(client_bucket(ip("2001:db8::1"), 1), ip("::"));
    }
}
