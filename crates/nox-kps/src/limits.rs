//! Connection admission: a global cap and a per-client-IP cap, keyed the same
//! way the node's ingress rate limiter keys clients (IPv4 address, IPv6
//! prefix), so one host cannot hold every connection slot.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};

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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
    fn prefix_lengths_mask_the_right_bits() {
        assert_eq!(client_bucket(ip("2001:db8::1"), 128), ip("2001:db8::1"));
        assert_eq!(client_bucket(ip("2001:db8:ffff::1"), 32), ip("2001:db8::"));
        assert_eq!(client_bucket(ip("2001:db8::1"), 1), ip("::"));
    }
}
