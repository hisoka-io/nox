//! IP-based connection filtering with subnet tracking and graduated bans.

use dashmap::DashMap;
use ipnet::{Ipv4Net, Ipv6Net};
use libp2p::Multiaddr;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
struct BanRecord {
    banned_at: Instant,
    ban_count: u32,
}

impl BanRecord {
    fn new() -> Self {
        Self {
            banned_at: Instant::now(),
            ban_count: 1,
        }
    }

    fn ban_duration(&self) -> Duration {
        match self.ban_count {
            1 => Duration::from_secs(60),   // 1 minute
            2 => Duration::from_secs(300),  // 5 minutes
            3 => Duration::from_secs(1800), // 30 minutes
            _ => Duration::from_secs(3600), // 1 hour (max)
        }
    }

    fn is_expired(&self) -> bool {
        self.banned_at.elapsed() >= self.ban_duration()
    }
}

use crate::config::ConnectionFilterConfig;

/// Connection filter with IP banning and per-subnet connection caps.
pub struct ConnectionFilter {
    denied_ips: DashMap<IpAddr, BanRecord>,
    subnet_counts: DashMap<Ipv4Net, u32>,
    subnet6_counts: DashMap<Ipv6Net, u32>,
    config: ConnectionFilterConfig,
}

impl ConnectionFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ConnectionFilterConfig::default())
    }

    #[must_use]
    pub fn with_config(config: ConnectionFilterConfig) -> Self {
        Self {
            denied_ips: DashMap::new(),
            subnet_counts: DashMap::new(),
            subnet6_counts: DashMap::new(),
            config,
        }
    }

    fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
        for proto in addr {
            match proto {
                libp2p::multiaddr::Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
                libp2p::multiaddr::Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
                _ => {}
            }
        }
        None
    }

    fn to_subnet(&self, ip: Ipv4Addr) -> Option<Ipv4Net> {
        Ipv4Net::new(ip, self.config.subnet_prefix_len)
            .ok()
            .map(|net| net.trunc())
    }

    fn to_ipv6_subnet(&self, ip: Ipv6Addr) -> Option<Ipv6Net> {
        Ipv6Net::new(ip, self.config.ipv6_subnet_prefix_len)
            .ok()
            .map(|net| net.trunc())
    }

    pub fn is_allowed(&self, addr: &Multiaddr) -> bool {
        let Some(ip) = Self::extract_ip(addr) else {
            // Cannot determine IP from Multiaddr -- deny by default to prevent
            // bypassing IP bans via non-IP transports (DNS, circuit relay, etc.)
            warn!(addr = %addr, "Denying connection: cannot extract IP for filtering");
            return false;
        };

        if let Some(record) = self.denied_ips.get(&ip) {
            if !record.is_expired() {
                debug!(ip = %ip, "Rejecting banned IP");
                return false;
            }
        }

        match ip {
            IpAddr::V4(ipv4) => {
                if let Some(subnet) = self.to_subnet(ipv4) {
                    if let Some(count) = self.subnet_counts.get(&subnet) {
                        if *count >= self.config.max_per_subnet {
                            debug!(subnet = %subnet, count = *count, "Rejecting connection: IPv4 subnet limit reached");
                            return false;
                        }
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                if let Some(subnet) = self.to_ipv6_subnet(ipv6) {
                    if let Some(count) = self.subnet6_counts.get(&subnet) {
                        if *count >= self.config.max_per_subnet {
                            debug!(subnet = %subnet, count = *count, "Rejecting connection: IPv6 subnet limit reached");
                            return false;
                        }
                    }
                }
            }
        }

        true
    }

    pub fn register_connection(&self, addr: &Multiaddr) {
        match Self::extract_ip(addr) {
            Some(IpAddr::V4(ipv4)) => {
                if let Some(subnet) = self.to_subnet(ipv4) {
                    self.subnet_counts
                        .entry(subnet)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    debug!(subnet = %subnet, "Registered IPv4 connection, new count: {}",
                        self.subnet_counts.get(&subnet).map_or(0, |c| *c));
                }
            }
            Some(IpAddr::V6(ipv6)) => {
                if let Some(subnet) = self.to_ipv6_subnet(ipv6) {
                    self.subnet6_counts
                        .entry(subnet)
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                    debug!(subnet = %subnet, "Registered IPv6 connection, new count: {}",
                        self.subnet6_counts.get(&subnet).map_or(0, |c| *c));
                }
            }
            None => {}
        }
    }

    pub fn unregister_connection(&self, addr: &Multiaddr) {
        match Self::extract_ip(addr) {
            Some(IpAddr::V4(ipv4)) => {
                if let Some(subnet) = self.to_subnet(ipv4) {
                    if let Some(mut count) = self.subnet_counts.get_mut(&subnet) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
            Some(IpAddr::V6(ipv6)) => {
                if let Some(subnet) = self.to_ipv6_subnet(ipv6) {
                    if let Some(mut count) = self.subnet6_counts.get_mut(&subnet) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
            None => {}
        }
    }

    /// Increments ban count on repeat offenders for graduated duration.
    pub fn ban_ip(&self, addr: &Multiaddr) {
        if let Some(ip) = Self::extract_ip(addr) {
            self.denied_ips
                .entry(ip)
                .and_modify(|record| {
                    record.ban_count += 1;
                    record.banned_at = Instant::now();
                    warn!(ip = %ip, ban_count = record.ban_count,
                        duration_secs = record.ban_duration().as_secs(),
                        "Re-banning IP with escalated duration");
                })
                .or_insert_with(|| {
                    warn!(ip = %ip, "Banning IP for 60 seconds");
                    BanRecord::new()
                });
        }
    }

    pub fn ban_ip_direct(&self, ip: IpAddr) {
        self.denied_ips
            .entry(ip)
            .and_modify(|record| {
                record.ban_count += 1;
                record.banned_at = Instant::now();
            })
            .or_insert_with(BanRecord::new);
    }

    #[must_use]
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.denied_ips.get(ip).is_some_and(|r| !r.is_expired())
    }

    #[must_use]
    pub fn banned_count(&self) -> usize {
        self.denied_ips.len()
    }

    #[must_use]
    pub fn get_subnet_count(&self, addr: &Multiaddr) -> Option<u32> {
        match Self::extract_ip(addr) {
            Some(IpAddr::V4(ipv4)) => {
                if let Some(subnet) = self.to_subnet(ipv4) {
                    return self.subnet_counts.get(&subnet).map(|c| *c);
                }
            }
            Some(IpAddr::V6(ipv6)) => {
                if let Some(subnet) = self.to_ipv6_subnet(ipv6) {
                    return self.subnet6_counts.get(&subnet).map(|c| *c);
                }
            }
            None => {}
        }
        None
    }

    pub fn cleanup_expired(&self) {
        self.denied_ips.retain(|ip, record| {
            let keep = !record.is_expired();
            if !keep {
                debug!(ip = %ip, "Removing expired ban");
            }
            keep
        });

        self.subnet_counts.retain(|subnet, count| {
            let keep = *count > 0;
            if !keep {
                debug!(subnet = %subnet, "Removing empty IPv4 subnet counter");
            }
            keep
        });

        self.subnet6_counts.retain(|subnet, count| {
            let keep = *count > 0;
            if !keep {
                debug!(subnet = %subnet, "Removing empty IPv6 subnet counter");
            }
            keep
        });
    }
}

impl Default for ConnectionFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(ip: &str) -> Multiaddr {
        format!("/ip4/{}/tcp/9000", ip).parse().expect("valid addr")
    }

    #[test]
    fn test_allows_normal_connection() {
        let filter = ConnectionFilter::new();
        let addr = make_addr("192.168.1.1");

        assert!(filter.is_allowed(&addr));
    }

    #[test]
    fn test_blocks_banned_ip() {
        let filter = ConnectionFilter::new();
        let addr = make_addr("192.168.1.1");

        filter.ban_ip(&addr);

        assert!(!filter.is_allowed(&addr));
    }

    #[test]
    fn test_subnet_limits() {
        let filter = ConnectionFilter::with_config(ConnectionFilterConfig {
            max_per_subnet: 2,
            subnet_prefix_len: 24,
            ipv6_subnet_prefix_len: 48,
        });

        // Register 2 connections from same /24
        filter.register_connection(&make_addr("192.168.1.1"));
        filter.register_connection(&make_addr("192.168.1.2"));

        // 3rd should be rejected
        assert!(!filter.is_allowed(&make_addr("192.168.1.3")));

        // Different subnet should be fine
        assert!(filter.is_allowed(&make_addr("192.168.2.1")));
    }

    #[test]
    fn test_graduated_bans() {
        let filter = ConnectionFilter::new();
        let addr = make_addr("192.168.1.1");

        // First ban: 60 seconds
        filter.ban_ip(&addr);
        assert_eq!(
            filter
                .denied_ips
                .get(&IpAddr::V4("192.168.1.1".parse().expect("valid")))
                .map(|r| r.ban_duration()),
            Some(Duration::from_secs(60))
        );

        // Second ban: 5 minutes
        filter.ban_ip(&addr);
        assert_eq!(
            filter
                .denied_ips
                .get(&IpAddr::V4("192.168.1.1".parse().expect("valid")))
                .map(|r| r.ban_duration()),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn test_unregister_connection() {
        let filter = ConnectionFilter::new();
        let addr = make_addr("192.168.1.1");

        filter.register_connection(&addr);
        assert_eq!(filter.get_subnet_count(&addr), Some(1));

        filter.unregister_connection(&addr);
        assert_eq!(filter.get_subnet_count(&addr), Some(0));
    }
}
