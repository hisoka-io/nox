//! Host checks run at startup and by `check-config`.
//!
//! The kps listener gathers its WebRTC ICE candidates from interfaces named
//! `lo*`. When such an interface carries an address outside 127.0.0.0/8 and
//! `::1` (WSL2 adds 10.255.255.254/32, for example), browsers see a second host
//! candidate and most WebRTC dials end in `kps: HELLO timeout`; QUIC is not
//! affected. Fleet hosts carry only 127.0.0.1/8 and `::1` on `lo`.

use std::net::IpAddr;

/// One address on a loopback-named interface that is not a loopback address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraLoopbackAddress {
    pub interface: String,
    pub address: IpAddr,
}

/// Filters `(interface, address)` pairs down to the problematic ones.
#[must_use]
pub fn extra_loopback_addresses<I>(addresses: I) -> Vec<ExtraLoopbackAddress>
where
    I: IntoIterator<Item = (String, IpAddr)>,
{
    let mut out: Vec<ExtraLoopbackAddress> = addresses
        .into_iter()
        .filter(|(name, ip)| name.starts_with("lo") && !ip.to_canonical().is_loopback())
        .map(|(interface, address)| ExtraLoopbackAddress { interface, address })
        .collect();
    out.sort_by(|a, b| (&a.interface, a.address).cmp(&(&b.interface, b.address)));
    out.dedup();
    out
}

/// Lists this host's extra loopback addresses.
pub fn scan_host() -> Result<Vec<ExtraLoopbackAddress>, String> {
    let ifaces = webrtc_util::ifaces::ifaces().map_err(|e| e.to_string())?;
    Ok(extra_loopback_addresses(
        ifaces
            .into_iter()
            .filter_map(|i| i.addr.map(|a| (i.name, a.ip()))),
    ))
}

/// The operator-facing explanation for one finding.
#[must_use]
pub fn describe(extra: &ExtraLoopbackAddress) -> String {
    format!(
        "interface {} carries {}, which is not a loopback address; kps gathers WebRTC candidates from lo* interfaces, so browser dials to this listener can fail with \"kps: HELLO timeout\" (QUIC is unaffected). Remove the address from {} (ip addr del {}/32 dev {}) on hosts that serve browsers",
        extra.interface, extra.address, extra.interface, extra.address, extra.interface
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

    use super::*;

    fn pair(name: &str, ip: &str) -> (String, IpAddr) {
        (name.to_string(), ip.parse().unwrap())
    }

    #[test]
    fn flags_only_non_loopback_addresses_on_lo_interfaces() {
        let found = extra_loopback_addresses([
            pair("lo", "127.0.0.1"),
            pair("lo", "::1"),
            pair("lo", "10.255.255.254"),
            pair("lo", "10.255.255.254"),
            pair("eth0", "172.31.66.207"),
            pair("lo0", "127.0.0.2"),
        ]);
        assert_eq!(
            found,
            vec![ExtraLoopbackAddress {
                interface: "lo".into(),
                address: "10.255.255.254".parse().unwrap(),
            }]
        );
        assert!(describe(&found[0]).contains("HELLO timeout"));
    }

    #[test]
    fn a_clean_host_has_no_findings() {
        assert!(extra_loopback_addresses([pair("lo", "127.0.0.1"), pair("lo", "::1")]).is_empty());
    }

    #[test]
    fn the_host_scan_runs() {
        scan_host().unwrap();
    }
}
