//! SSRF protection for exit node outbound requests (HTTP and RPC handlers).

use std::net::IpAddr;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("SSRF blocked: {reason}")]
    Blocked { reason: String },

    #[error("Domain not allowed: {domain}")]
    DomainNotAllowed { domain: String },

    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
}

pub fn is_ip_allowed(ip: IpAddr, allow_private: bool) -> Result<(), SsrfError> {
    if ip.is_loopback() && !allow_private {
        return Err(SsrfError::Blocked {
            reason: "Loopback address blocked".into(),
        });
    }

    if ip.is_unspecified() {
        return Err(SsrfError::Blocked {
            reason: "Unspecified address blocked".into(),
        });
    }

    // IPv4-mapped IPv6 (::ffff:x.x.x.x) -- extract inner IPv4 and re-validate
    if let IpAddr::V6(ipv6) = ip {
        if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
            return is_ip_allowed(IpAddr::V4(mapped_v4), allow_private);
        }
    }

    if !allow_private {
        match ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_private() {
                    return Err(SsrfError::Blocked {
                        reason: format!("Private IPv4 {ip} blocked"),
                    });
                }
                if ipv4.is_link_local() {
                    return Err(SsrfError::Blocked {
                        reason: format!("Link-local IPv4 {ip} blocked"),
                    });
                }
                if ipv4.is_broadcast() {
                    return Err(SsrfError::Blocked {
                        reason: "Broadcast address blocked".into(),
                    });
                }
                if ipv4.is_documentation() {
                    return Err(SsrfError::Blocked {
                        reason: "Documentation range blocked".into(),
                    });
                }
                // CGNAT: 100.64.0.0/10
                let octets = ipv4.octets();
                if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                    return Err(SsrfError::Blocked {
                        reason: format!("CGNAT IPv4 {ip} blocked"),
                    });
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_multicast() {
                    return Err(SsrfError::Blocked {
                        reason: "Multicast address blocked".into(),
                    });
                }
                let segments = ipv6.segments();
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return Err(SsrfError::Blocked {
                        reason: format!("IPv6 ULA {ip} blocked"),
                    });
                }
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return Err(SsrfError::Blocked {
                        reason: format!("IPv6 link-local {ip} blocked"),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Single DNS resolution to prevent rebinding attacks.
pub async fn resolve_hostname(hostname: &str, port: u16) -> Result<IpAddr, SsrfError> {
    let addr_str = format!("{hostname}:{port}");
    let mut addrs = tokio::net::lookup_host(addr_str)
        .await
        .map_err(|e| SsrfError::DnsResolutionFailed(e.to_string()))?;

    addrs
        .next()
        .map(|addr| addr.ip())
        .ok_or_else(|| SsrfError::DnsResolutionFailed("No addresses found".into()))
}

/// `None` whitelist means all domains allowed (open-web model).
pub fn is_domain_allowed(domain: &str, whitelist: &Option<Vec<String>>) -> Result<(), SsrfError> {
    if let Some(allowed) = whitelist {
        let domain_lower = domain.to_lowercase();
        let allowed = allowed.iter().any(|d| {
            let d_lower = d.to_lowercase();
            // Exact match or subdomain match
            domain_lower == d_lower || domain_lower.ends_with(&format!(".{d_lower}"))
        });
        if !allowed {
            return Err(SsrfError::DomainNotAllowed {
                domain: domain.into(),
            });
        }
    }
    Ok(())
}

/// Full SSRF validation: parse URL, validate scheme, resolve DNS once, check IP.
pub async fn validate_url_ssrf(
    url_str: &str,
    allow_private_ips: bool,
) -> Result<(IpAddr, Url), SsrfError> {
    let url = Url::parse(url_str).map_err(|e| SsrfError::InvalidUrl(format!("{url_str}: {e}")))?;

    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(SsrfError::InvalidUrl(format!(
            "Unsupported scheme: {scheme} (only http/https allowed)"
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| SsrfError::InvalidUrl("No host in URL".into()))?;

    let port = url
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let resolved_ip = resolve_hostname(host, port).await?;
    is_ip_allowed(resolved_ip, allow_private_ips)?;

    Ok((resolved_ip, url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_ip_allowed_blocks_loopback() {
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), false).is_err());
        assert!(is_ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), false).is_err());
    }

    #[test]
    fn test_is_ip_allowed_allows_loopback_when_private_allowed() {
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), true).is_ok());
        assert!(is_ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), true).is_ok());
    }

    #[test]
    fn test_is_ip_allowed_blocks_private() {
        // 10.0.0.0/8
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), false).is_err());
        // 172.16.0.0/12
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), false).is_err());
        // 192.168.0.0/16
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), false).is_err());
    }

    #[test]
    fn test_is_ip_allowed_blocks_link_local() {
        // 169.254.x.x
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), false).is_err());
    }

    #[test]
    fn test_is_ip_allowed_public_ok() {
        // Google DNS
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), false).is_ok());
        // Cloudflare
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), false).is_ok());
    }

    #[test]
    fn test_is_ip_allowed_private_when_enabled() {
        // With allow_private = true, private IPs should be allowed
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), true).is_ok());
        // Loopback is also allowed when allow_private = true (needed for local Anvil testing)
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST), true).is_ok());
    }

    #[test]
    fn test_is_ip_allowed_blocks_unspecified() {
        // 0.0.0.0 -- always blocked regardless of allow_private
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), false).is_err());
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true).is_err());
        // :: (IPv6 unspecified) -- always blocked
        assert!(is_ip_allowed(IpAddr::V6(Ipv6Addr::UNSPECIFIED), false).is_err());
        assert!(is_ip_allowed(IpAddr::V6(Ipv6Addr::UNSPECIFIED), true).is_err());
    }

    #[test]
    fn test_is_ip_allowed_blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 -- loopback wrapped in IPv4-mapped IPv6
        let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().expect("valid mapped loopback");
        assert!(is_ip_allowed(mapped_loopback, false).is_err());

        // ::ffff:192.168.1.1 -- private range wrapped in IPv4-mapped IPv6
        let mapped_private: IpAddr = "::ffff:192.168.1.1".parse().expect("valid mapped private");
        assert!(is_ip_allowed(mapped_private, false).is_err());

        // ::ffff:10.0.0.1 -- another private range
        let mapped_ten: IpAddr = "::ffff:10.0.0.1".parse().expect("valid mapped 10.x");
        assert!(is_ip_allowed(mapped_ten, false).is_err());

        // ::ffff:100.64.0.1 -- CGNAT wrapped in IPv4-mapped IPv6
        let mapped_cgnat: IpAddr = "::ffff:100.64.0.1".parse().expect("valid mapped CGNAT");
        assert!(is_ip_allowed(mapped_cgnat, false).is_err());

        // ::ffff:8.8.8.8 -- public IP wrapped should still be allowed
        let mapped_public: IpAddr = "::ffff:8.8.8.8".parse().expect("valid mapped public");
        assert!(is_ip_allowed(mapped_public, false).is_ok());
    }

    #[test]
    fn test_is_ip_allowed_blocks_cgnat() {
        // CGNAT range: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
        // Start of range
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), false).is_err());
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), false).is_err());
        // Middle of range
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(100, 100, 50, 25)), false).is_err());
        // End of range
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255)), false).is_err());
        // Just outside the range -- should be allowed
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 0)), false).is_ok());
        assert!(is_ip_allowed(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255)), false).is_ok());
    }

    #[test]
    fn test_domain_whitelist() {
        let whitelist = Some(vec!["example.com".to_string(), "api.test.org".to_string()]);

        assert!(is_domain_allowed("example.com", &whitelist).is_ok());
        assert!(is_domain_allowed("sub.example.com", &whitelist).is_ok());
        assert!(is_domain_allowed("api.test.org", &whitelist).is_ok());
        assert!(is_domain_allowed("evil.com", &whitelist).is_err());
    }

    #[test]
    fn test_domain_no_whitelist() {
        assert!(is_domain_allowed("anything.com", &None).is_ok());
    }

    #[tokio::test]
    async fn test_validate_url_rejects_invalid_scheme() {
        let result = validate_url_ssrf("ftp://example.com", false).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SsrfError::InvalidUrl(msg) => assert!(msg.contains("Unsupported scheme")),
            other => panic!("Expected InvalidUrl, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_validate_url_rejects_garbage() {
        let result = validate_url_ssrf("not a url", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_url_rejects_no_host() {
        let result = validate_url_ssrf("http://", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_url_blocks_localhost() {
        let result = validate_url_ssrf("http://127.0.0.1:8545", false).await;
        assert!(result.is_err());
    }
}
