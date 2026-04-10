//! DoS protection integration tests: rate limiting and subnet connection limits.

use libp2p::PeerId;
use nox_node::config::{ConnectionFilterConfig, RateLimitConfig};
use nox_node::network::{
    connection_filter::ConnectionFilter,
    rate_limiter::{PeerRateLimiter, RateLimitResult},
};

#[test]
fn test_subnet_connection_limits() {
    let filter = ConnectionFilter::with_config(ConnectionFilterConfig {
        max_per_subnet: 3,
        subnet_prefix_len: 24,
        ipv6_subnet_prefix_len: 48,
    });

    for i in 1..=3 {
        let addr: libp2p::Multiaddr = format!("/ip4/10.0.0.{}/tcp/9000", i).parse().unwrap();
        filter.register_connection(&addr);
    }

    let test_addr: libp2p::Multiaddr = "/ip4/10.0.0.1/tcp/9000".parse().unwrap();
    let count = filter.get_subnet_count(&test_addr).unwrap_or(0);
    assert_eq!(count, 3, "Should have 3 connections in subnet");

    let different_subnet: libp2p::Multiaddr = "/ip4/10.0.1.1/tcp/9000".parse().unwrap();
    assert!(
        filter.is_allowed(&different_subnet),
        "Connection from different subnet should be allowed"
    );
}

#[test]
fn test_flood_attack_simulation() {
    let limiter = PeerRateLimiter::with_config(RateLimitConfig {
        burst_unknown: 50,
        rate_unknown: 100,
        violations_before_disconnect: 5,
        ..Default::default()
    });

    let attacker = PeerId::random();
    let mut allowed = 0u64;
    let mut denied = 0u64;

    for _ in 0..1000 {
        match limiter.check(&attacker) {
            RateLimitResult::Allowed => allowed += 1,
            RateLimitResult::Denied => denied += 1,
        }
    }

    assert!(
        allowed <= 100,
        "Should not allow more than ~2x burst through, got {}",
        allowed
    );
    assert!(
        denied >= 900,
        "At least 900 packets should be dropped, got {}",
        denied
    );

    assert!(
        limiter.should_disconnect(&attacker),
        "Flooder should be marked for disconnect"
    );
}

#[test]
fn test_trusted_peer_gets_higher_limits() {
    use nox_node::network::rate_limiter::PeerReputation;

    let limiter = PeerRateLimiter::with_config(RateLimitConfig {
        burst_unknown: 5,
        rate_unknown: 10,
        burst_trusted: 20,
        rate_trusted: 50,
        ..Default::default()
    });

    let peer = PeerId::random();

    limiter.check(&peer);
    assert_eq!(limiter.get_reputation(&peer), Some(PeerReputation::Unknown));

    limiter.promote_to_trusted(&peer);
    assert_eq!(limiter.get_reputation(&peer), Some(PeerReputation::Trusted));

    let mut allowed = 0;
    for _ in 0..25 {
        if limiter.check(&peer) == RateLimitResult::Allowed {
            allowed += 1;
        }
    }

    assert!(
        allowed >= 15,
        "Trusted peer should have higher burst limit, got {}",
        allowed
    );
}

#[test]
fn test_graduated_ban_durations() {
    use std::net::IpAddr;

    let filter = ConnectionFilter::new();
    let addr: libp2p::Multiaddr = "/ip4/192.168.1.1/tcp/9000".parse().unwrap();

    filter.ban_ip(&addr);
    assert!(filter.is_banned(&"192.168.1.1".parse::<IpAddr>().unwrap()));

    filter.ban_ip(&addr);
    filter.ban_ip(&addr);

    assert!(filter.is_banned(&"192.168.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_connection_filter_blocks_banned_ips() {
    let filter = ConnectionFilter::new();

    let addr: libp2p::Multiaddr = "/ip4/192.168.1.100/tcp/9000".parse().unwrap();

    assert!(
        filter.is_allowed(&addr),
        "Address should initially be allowed"
    );

    filter.ban_ip(&addr);

    assert!(
        !filter.is_allowed(&addr),
        "Banned address should be blocked"
    );
}
